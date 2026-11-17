import hashlib
import os
import re
import time
import requests
from dotenv import load_dotenv
from services.prompts import build_cve_search_prompt, build_remediation_prompt

load_dotenv()

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

_SESSION = requests.Session()


def _sanitize_error(msg, secret_key=None):
    text = str(msg or "")
    if secret_key:
        text = text.replace(secret_key, "***")
    text = re.sub(r"([?&]key=)[^&\s]+", r"\1***", text)
    return text


def compute_ai_cache_key(finding, prompt_type, provider):
    """Stable hash key for caching AI responses across identical components."""
    payload = "|".join([
        str(finding.get("component") or ""),
        str(finding.get("component_name") or ""),
        str(finding.get("version") or ""),
        str(finding.get("title") or ""),
        str(prompt_type or ""),
        str(provider or ""),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LLMClient:
    """Unified HTTP client with retry/backoff for Gemini and Anthropic."""

    def __init__(self, provider, api_key=None, session=None):
        self.provider = (provider or "gemini").strip().lower()
        self.api_key = api_key
        self.session = session or _SESSION

    def generate_text(self, prompt, max_retries=3):
        if self.provider == "gemini":
            return self._call_gemini(prompt, max_retries=max_retries)
        if self.provider in ("anthropic", "claude"):
            return self._call_anthropic(prompt, max_retries=max_retries)
        return f"Error: Provider '{self.provider}' tidak didukung. Pilih 'gemini' atau 'claude'."

    def _post_with_retry(self, url, headers, body, timeout, label, secret_key, max_retries=3):
        last_err = None
        for attempt in range(max_retries):
            try:
                resp = self.session.post(url, headers=headers, json=body, timeout=timeout)
                if resp.status_code == 429:
                    wait = (2 ** attempt) * 5
                    last_err = f"Rate limit {label} (HTTP 429). Coba lagi dalam {wait}s."
                    if attempt < max_retries - 1:
                        time.sleep(wait)
                        continue
                    return None, f"Error: {last_err}"
                if resp.status_code >= 500:
                    last_err = f"Server {label} error (HTTP {resp.status_code}): {_sanitize_error(resp.text[:200], secret_key)}"
                    if attempt < max_retries - 1:
                        time.sleep(3)
                        continue
                    return None, f"Error: {last_err}"
                resp.raise_for_status()
                return resp.json(), None
            except requests.exceptions.Timeout:
                last_err = f"Timeout memanggil {label} setelah {timeout}s."
                if attempt < max_retries - 1:
                    time.sleep(3)
                    continue
                return None, f"Error: {last_err}"
            except Exception as exc:
                last_err = f"Error memanggil {label}: {_sanitize_error(exc, secret_key)}"
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                return None, f"Error: {last_err}"
        return None, f"Error: {last_err}"

    def _call_gemini(self, prompt, max_retries=3):
        key = self.api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not key:
            return "Error: GEMINI_API_KEY tidak ditemukan di environment. Isi .env lalu restart Flask dan Celery worker."
        model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
        timeout = int(os.getenv("GEMINI_TIMEOUT", "180"))
        url = f"{GEMINI_API_BASE}/{model}:generateContent"
        headers = {
            "x-goog-api-key": key,
            "content-type": "application/json",
        }
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
        }
        data, err = self._post_with_retry(url, headers, body, timeout, f"Gemini ({model})", key, max_retries)
        if err:
            return err
        candidates = (data or {}).get("candidates", []) or []
        if not candidates:
            return "Error: Tidak ada kandidat respons dari Gemini."
        parts = candidates[0].get("content", {}).get("parts", []) or []
        text = "".join(p.get("text", "") for p in parts)
        if text:
            return text
        return f"Error: Gemini tidak mengembalikan teks respons (finish_reason={candidates[0].get('finishReason')})."

    def _call_anthropic(self, prompt, max_retries=3):
        key = self.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            return "Error: ANTHROPIC_API_KEY tidak ditemukan di environment. Isi .env lalu restart Flask dan Celery worker."
        model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
        timeout = int(os.getenv("ANTHROPIC_TIMEOUT", "60"))
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        data, err = self._post_with_retry(ANTHROPIC_API_URL, headers, body, timeout, f"Claude ({model})", key, max_retries)
        if err:
            return err
        content_list = (data or {}).get("content", [])
        text = "".join(item.get("text", "") for item in content_list if item.get("type") == "text")
        return text if text else "Error: Claude tidak mengembalikan teks respons."


def call_llm_text(prompt, provider, api_key=None):
    return LLMClient(provider=provider, api_key=api_key).generate_text(prompt)


def build_prompt_for_finding(finding_dict):
    """Choose remediation or CVE search prompt based on finding confidence."""
    if finding_dict.get("confidence") in ("Confirmed", "Cross-verified"):
        return "remediation", build_remediation_prompt(finding_dict)
    return "cve_search", build_cve_search_prompt(finding_dict)
