def build_remediation_prompt(finding, tech_stack=None):
    """Build dynamic remediation prompt for Confirmed / Cross-verified findings."""
    comp_name = finding.get("component_name") or "komponen WordPress"
    comp_type = finding.get("component") or "wordpress"
    comp_ver = finding.get("version") or "Tidak diketahui"
    title = finding.get("title") or "-"
    severity = (finding.get("severity") or "medium").upper()
    confidence = finding.get("confidence") or "Confirmed"
    cve_id = finding.get("cve_id") or "Tidak ada"
    evidence = finding.get("evidence_summary") or "-"
    stack_str = ", ".join(list(tech_stack)[:6]) if tech_stack else "-"

    return f"""Analisis temuan keamanan berikut pada target WordPress:
- Komponen: {comp_name} ({comp_type})
- Versi: {comp_ver}
- Judul Temuan: {title}
- Severity: {severity}
- Confidence: {confidence}
- CVE: {cve_id}
- Tech Stack (WhatWeb): {stack_str}
- Bukti:
{evidence}

Berikan langkah mitigasi konkret untuk administrator WordPress (dalam Bahasa Indonesia):
1. Tindakan Utama (update/patch versi aman)
2. Mitigasi Sementara (WAF/.htaccess/nonaktifkan fitur bila belum bisa update)
3. Verifikasi perbaikan
4. Hardening preventif."""


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
