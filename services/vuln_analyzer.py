import os
import json
import requests
import time
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
ANTHROPIC_TIMEOUT = int(os.getenv("ANTHROPIC_TIMEOUT", "60"))

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_TIMEOUT = int(os.getenv("GEMINI_TIMEOUT", "180"))

EMPTY_ANALYSIS = {
    "findings": [],
    "overall_severity": None,
    "overall_summary": None,
    "overall_recommendations": []
}


def _extract_vulnerabilities(raw_output):
    try:
        data = json.loads(raw_output) if raw_output else {}
    except (json.JSONDecodeError, TypeError):
        return []

    findings = []

    version_data = data.get("version", {}) or {}
    for v in version_data.get("vulnerabilities", []) or []:
        findings.append({
            "component": "core",
            "component_name": f"WordPress {version_data.get('number', '')}".strip(),
            "title": v.get("title"),
            "fixed_in": v.get("fixed_in"),
            "references": v.get("references", {}) or {}
        })

    main_theme = data.get("main_theme", {}) or {}
    for v in main_theme.get("vulnerabilities", []) or []:
        findings.append({
            "component": "theme",
            "component_name": main_theme.get("slug"),
            "title": v.get("title"),
            "fixed_in": v.get("fixed_in"),
            "references": v.get("references", {}) or {}
        })

    plugins = data.get("plugins", {}) or {}
    if isinstance(plugins, dict):
        for slug, plugin_data in plugins.items():
            if slug == "*" or not isinstance(plugin_data, dict):
                continue
            for v in plugin_data.get("vulnerabilities", []) or []:
                findings.append({
                    "component": "plugin",
                    "component_name": slug,
                    "title": v.get("title"),
                    "fixed_in": v.get("fixed_in"),
                    "references": v.get("references", {}) or {}
                })

    return findings


def _build_prompt(findings, target_url):
    return f"""You are a senior web application security engineer analyzing WPScan vulnerabilities for {target_url}.

Below is a JSON list of {len(findings)} vulnerabilities detected. For EACH vulnerability, strictly maintaining the original index order:

1. Copy the original "title", "component", and "component_name" fields unchanged.
2. Extract existing CVE IDs from "references.cve". If none exist, return an empty list []. NEVER invent, hallucinate, or guess CVE IDs.
3. Assign a severity ("critical", "high", "medium", "low") based on CVSS/CVE context, component impact, and exploitability.
4. Provide a concise 1-2 sentence technical reason for the assigned severity.
5. Provide 5 HIGHLY SPECIFIC (IF NEEDED), ACTIONABLE remediation steps. Do NOT just say "update plugin". Include:
   - Primary fix (e.g., exact target version to update or patch).
   - Temporary mitigation/workaround if immediate update is not possible (e.g., disable feature, WAF rule, or code sanitization context).
   - Hardening or preventative measures relevant to this specific flaw.

Also provide a holistic security assessment across all findings combined.

Vulnerabilities Input Data:
{json.dumps(findings, indent=2)}

CRITICAL REQUIREMENT: Respond ONLY with a single, valid JSON object (no markdown code blocks, no text before/after). Use this exact structure:
{{
  "findings": [
    {{
      "index": 0,
      "component": "plugin",
      "component_name": "contact-form-7",
      "title": "...",
      "cve_ids": ["CVE-2023-XXXX"],
      "severity": "high",
      "severity_reason": "...",
      "recommendations": [
        "Primary: Update contact-form-7 to version X.X.X or higher immediately.",
        "Mitigation: Disable file upload inputs in contact form settings until patch is applied.",
        "Hardening: Add request filtering rule in .htaccess to block suspicious payload patterns to wp-json endpoint."
      ]
    }}
  ],
  "overall_severity": "high",
  "overall_summary": "...",
  "overall_recommendations": [
    "...",
    "..."
  ]
}}"""


def _build_single_vuln_prompt(vuln, target_url):
    cve_str = ", ".join(vuln.get("cve_ids", [])) if vuln.get("cve_ids") else "Tidak ada"
    references = vuln.get("references", {})
    ref_urls = references.get("url", []) if isinstance(references, dict) else []
    ref_str = "\n".join([f"- {url}" for url in ref_urls]) if ref_urls else "Tidak ada"

    return f"""You are a senior web application security engineer and penetration tester analyzing a specific vulnerability for the WordPress website: {target_url}.

Analyze the following vulnerability:
- Component Type: {vuln.get('component')}
- Component Name: {vuln.get('component_name')}
- Vulnerability Title: {vuln.get('title')}
- CVE IDs: {cve_str}
- Fixed in Version: {vuln.get('fixed_in') or 'N/A'}
- Reference URLs:
{ref_str}

Please perform a deep technical analysis of this vulnerability and return a JSON object containing:
1. "severity": Assign one of "critical", "high", "medium", or "low" based on the CVSS context, component impact, and exploitability.
2. "severity_reason": Provide a highly detailed, professional technical explanation (in Indonesian, 2-3 sentences) of why this severity was assigned, discussing the potential impact (e.g. Privilege Escalation, Remote Code Execution, XSS) and exploit ease.
3. "recommendations": Provide 4-5 HIGHLY SPECIFIC, ACTIONABLE, and concrete remediation steps (in Indonesian). Do NOT just say "update plugin". You must include:
   - **Tindakan Utama (Primary Fix)**: Langkah pembaruan komponen ke versi aman atau patch yang harus diterapkan.
   - **Mitigasi Sementara (Temporary Workaround)**: Jika update tidak bisa segera dilakukan, sebutkan konfigurasi khusus (misal custom WAF rules, aturan di .htaccess, menonaktifkan fitur/modul spesifik) untuk mencegah eksploitasi.
   - **Verifikasi (Verification)**: Cara memverifikasi apakah celah keamanan tersebut benar-benar telah tertutup.
   - **Pengerasan Sistem (Hardening)**: Langkah preventif jangka panjang untuk memperkuat sistem dari serangan serupa.

CRITICAL REQUIREMENT: Respond ONLY with a single, valid JSON object (no markdown formatting, no code blocks/fences like ```json, no text before/after). Use this exact structure:
{{
  "severity": "high",
  "severity_reason": "Alasan teknis detail...",
  "recommendations": [
    "Utama: Perbarui plugin ke versi X.Y.Z atau lebih tinggi.",
    "Mitigasi: Nonaktifkan fitur unggah berkas sementara dari dashboard plugin.",
    "Verifikasi: Jalankan kembali pemindaian WPScan untuk memastikan versi plugin telah terupdate.",
    "Pengerasan: Batasi akses langsung ke direktori wp-content/uploads/ menggunakan modul .htaccess."
  ]
}}"""



def _strip_fences(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return text.strip()


def _call_gemini(prompt, api_key, max_retries=3, max_continuations=4):
    url = f"{GEMINI_API_BASE}/{GEMINI_MODEL}:generateContent?key={api_key}"

    def _request(contents):
        body = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 8192,
                "responseMimeType": "application/json"
            }
        }
        resp = None
        for attempt in range(max_retries):
            try:
                resp = requests.post(url, json=body, timeout=GEMINI_TIMEOUT)
                if resp.status_code == 429:
                    wait = (2 ** attempt) * 5
                    print(f"[WARN] Hit Rate limit (429). Retrying in {wait}s...")
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout:
                print(f"[WARN] Timeout pada percobaan ke-{attempt + 1}. Retrying...")
                if attempt == max_retries - 1:
                    raise TimeoutError("Gemini API tidak merespons hingga batas timeout berakhir.")
                time.sleep(3)
        raise RuntimeError(f"Gagal request setelah {max_retries} percobaan (kemungkinan rate limit terus-menerus).")

    contents = [{"role": "user", "parts": [{"text": prompt}]}]
    data = _request(contents)

    full_text = ""
    for _ in range(max_continuations + 1):
        candidates = data.get("candidates", []) or []
        if not candidates:
            raise ValueError(f"Gemini tidak mengembalikan kandidat respons: {data}")

        cand = candidates[0]
        parts = cand.get("content", {}).get("parts", []) or []
        chunk_text = "".join(p.get("text", "") for p in parts)
        full_text += chunk_text

        finish_reason = cand.get("finishReason", "")

        if finish_reason != "MAX_TOKENS":
            break

        print("[WARN] Output kepotong (MAX_TOKENS). Meminta lanjutan...")

        contents = [
            {"role": "user", "parts": [{"text": prompt}]},
            {"role": "model", "parts": [{"text": chunk_text}]},
            {"role": "user", "parts": [{"text": (
                "Output kamu terpotong. Lanjutkan PERSIS dari karakter terakhir "
                "tanpa mengulang bagian sebelumnya, tanpa penjelasan tambahan, "
                "sampai JSON valid dan lengkap."
            )}]},
        ]
        data = _request(contents)
    else:
        print("[WARN] Batas max_continuations tercapai, JSON mungkin masih belum lengkap.")

    return _parse_json_safely(full_text)


def _parse_json_safely(text):
    text = _strip_fences(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON tetap tidak valid setelah digabung: {e}")
        try:
            from json_repair import repair_json
            repaired = repair_json(text)
            return json.loads(repaired)
        except Exception:
            raise ValueError(f"Gagal parse JSON dari Gemini meski sudah di-continue:\n{text[:2000]}...")


def _call_anthropic(prompt, api_key):
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    body = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}]
    }
    resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=ANTHROPIC_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    content_list = data.get("content", [])
    text = "".join(item.get("text", "") for item in content_list if item.get("type") == "text")
    return _parse_json_safely(text)


def analyze_vulnerabilities(raw_output, target_url, api_key=None):
    findings = _extract_vulnerabilities(raw_output)
    if not findings:
        return None

    provider = os.getenv("VULN_ANALYZER_PROVIDER", "anthropic").strip().lower()
    prompt = _build_prompt(findings, target_url)

    try:
        if provider == "gemini":
            key = api_key or os.getenv("GEMINI_API_KEY")
            if not key:
                return {"error": "GEMINI_API_KEY tidak ditemukan di environment", **EMPTY_ANALYSIS}
            return _call_gemini(prompt, key)

        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            return {"error": "ANTHROPIC_API_KEY tidak ditemukan di environment", **EMPTY_ANALYSIS}
        return _call_anthropic(prompt, key)

    except requests.exceptions.RequestException as e:
        return {"error": f"Gagal menghubungi API {provider}: {e}", **EMPTY_ANALYSIS}
    except (json.JSONDecodeError, ValueError) as e:
        return {"error": f"Gagal parse respons {provider} sebagai JSON: {e}", **EMPTY_ANALYSIS}
    except Exception as e:
        return {"error": f"Terjadi kesalahan tak terduga saat analisis ({provider}): {e}", **EMPTY_ANALYSIS}


def analyze_single_vulnerability(vuln_data, target_url, provider, api_key=None):
    prompt = _build_single_vuln_prompt(vuln_data, target_url)
    provider_name = provider.strip().lower()

    try:
        if provider_name == "gemini":
            key = api_key or os.getenv("GEMINI_API_KEY")
            if not key:
                return {"error": "GEMINI_API_KEY tidak ditemukan di environment"}
            return _call_gemini(prompt, key)

        elif provider_name in ("anthropic", "claude"):
            key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not key:
                return {"error": "ANTHROPIC_API_KEY tidak ditemukan di environment"}
            return _call_anthropic(prompt, key)

        else:
            return {"error": f"Provider '{provider}' tidak didukung."}

    except requests.exceptions.RequestException as e:
        return {"error": f"Gagal menghubungi API {provider_name}: {e}"}
    except (json.JSONDecodeError, ValueError) as e:
        return {"error": f"Gagal parse respons {provider_name} sebagai JSON: {e}"}
    except Exception as e:
        return {"error": f"Terjadi kesalahan tak terduga saat analisis ({provider_name}): {e}"}


def build_cve_search_prompt(finding):
    """Prompt khusus 'Analisis & Pencarian CVE via Gen AI' - hanya NOMOR CVE, NAMA, dan LINK."""
    component = finding.get("component_name") or finding.get("component") or "komponen WordPress"
    version = finding.get("version") or "tidak diketahui"
    context = finding.get("title") or finding.get("evidence_summary") or ""
    return f"""Anda adalah asisten keamanan WordPress. Tugas Anda HANYA mencari CVE yang relevan untuk komponen berikut:
- Komponen: {component}
- Versi: {version}
- Konteks: {context}

CRITICAL REQUIREMENT - Jawab HANYA dengan format berikut (maksimal 5 CVE), tanpa teks lain:
CVE-2023-1234 - Nama CVE singkat
CVE-2023-5678 - Nama CVE singkat

Kemudian untuk SETIAP CVE di atas, cantumkan link NVD-nya pada baris terpisah:
https://nvd.nist.gov/vuln/detail/CVE-2023-1234
https://nvd.nist.gov/vuln/detail/CVE-2023-5678

JANGAN menambahkan mitigasi, rekomendasi, atau penjelasan apa pun selain NOMOR CVE, NAMA, dan LINK.
Jika tidak ada CVE yang relevan/terkonfirmasi, cukup tulis satu baris:
Tidak ada CVE yang diketahui untuk komponen ini."""


def call_llm_text(prompt, provider, api_key=None):
    provider_name = provider.strip().lower()

    if provider_name == "gemini":
        key = api_key or os.getenv("GEMINI_API_KEY")
        if not key:
            return "Error: GEMINI_API_KEY tidak ditemukan di environment. Isi .env lalu restart Flask dan Celery worker."
        url = f"{GEMINI_API_BASE}/{GEMINI_MODEL}:generateContent?key={key}"
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 8192
            }
        }
        last_err = None
        for attempt in range(3):
            try:
                resp = requests.post(url, json=body, timeout=GEMINI_TIMEOUT)
                if resp.status_code == 429:
                    wait = (2 ** attempt) * 5
                    last_err = f"Rate limit Gemini (HTTP 429). Coba lagi dalam {wait}s atau tunggu kuota pulih."
                    if attempt < 2:
                        time.sleep(wait)
                        continue
                    return f"Error: {last_err}"
                if resp.status_code >= 500:
                    last_err = f"Server Gemini error (HTTP {resp.status_code}): {resp.text[:200]}"
                    if attempt < 2:
                        time.sleep(3)
                        continue
                    return f"Error: {last_err}"
                resp.raise_for_status()
                data = resp.json()
                candidates = data.get("candidates", []) or []
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", []) or []
                    text = "".join(p.get("text", "") for p in parts)
                    if text:
                        return text
                    return "Error: Gemini tidak mengembalikan teks respons (finish_reason=" + \
                           str(candidates[0].get("finishReason")) + "). Coba lagi."
                return "Error: Tidak ada kandidat respons dari Gemini."
            except requests.exceptions.Timeout:
                last_err = f"Timeout memanggil Gemini ({GEMINI_MODEL}) setelah {GEMINI_TIMEOUT}s. " \
                           "Model ini lambat (~40-60s); ulangi lagi atau naikkan GEMINI_TIMEOUT di .env."
                if attempt < 2:
                    time.sleep(3)
                    continue
                return f"Error: {last_err}"
            except Exception as e:
                last_err = f"Error memanggil Gemini ({GEMINI_MODEL}): {e}"
                if attempt < 2:
                    time.sleep(2)
                    continue
                return f"Error: {last_err}"
        return f"Error: {last_err}"

    elif provider_name in ("anthropic", "claude"):
        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            return "Error: ANTHROPIC_API_KEY tidak ditemukan di environment. Isi .env lalu restart Flask dan Celery worker."
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        body = {
            "model": ANTHROPIC_MODEL,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }
        last_err = None
        for attempt in range(3):
            try:
                resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=ANTHROPIC_TIMEOUT)
                if resp.status_code == 429:
                    wait = (2 ** attempt) * 5
                    last_err = f"Rate limit Claude (HTTP 429). Coba lagi dalam {wait}s."
                    if attempt < 2:
                        time.sleep(wait)
                        continue
                    return f"Error: {last_err}"
                if resp.status_code >= 500:
                    last_err = f"Server Claude error (HTTP {resp.status_code}): {resp.text[:200]}"
                    if attempt < 2:
                        time.sleep(3)
                        continue
                    return f"Error: {last_err}"
                resp.raise_for_status()
                data = resp.json()
                content_list = data.get("content", [])
                text = "".join(item.get("text", "") for item in content_list if item.get("type") == "text")
                if text:
                    return text
                return "Error: Claude tidak mengembalikan teks respons."
            except requests.exceptions.Timeout:
                last_err = f"Timeout memanggil Claude ({ANTHROPIC_MODEL}) setelah {ANTHROPIC_TIMEOUT}s."
                if attempt < 2:
                    time.sleep(3)
                    continue
                return f"Error: {last_err}"
            except Exception as e:
                last_err = f"Error memanggil Claude ({ANTHROPIC_MODEL}): {e}"
                if attempt < 2:
                    time.sleep(2)
                    continue
                return f"Error: {last_err}"
        return f"Error: {last_err}"

    else:
        return f"Error: Provider '{provider}' tidak didukung. Pilih 'gemini' atau 'claude'."

