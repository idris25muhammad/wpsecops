"""
WordPress Hardening Checker (External / HTTP-only)
=====================================================
Mengaudit sebuah situs WordPress dari LUAR (tanpa akses shell/SSH) dengan
mencocokkan kondisi situs terhadap rekomendasi resmi WordPress:
https://developer.wordpress.org/advanced-administration/security/hardening/

PENTING - ETIKA & LEGALITAS:
- Hanya jalankan terhadap situs milik Anda sendiri, atau yang Anda punya izin
  tertulis untuk mengaudit (mis. milik institusi/klien dengan otorisasi resmi).
- Semua pengecekan bersifat pasif/non-intrusif (GET/HEAD request biasa).
- Tidak melakukan exploitation, brute-force, atau fuzzing agresif.
"""

import json
import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

requests.packages.urllib3.disable_warnings()

USER_AGENT = "WP-Hardening-Checker/1.0 (+educational-security-audit)"
TIMEOUT = 10


class Result:
    """Satu baris hasil pengecekan."""

    def __init__(self, check_id, title, status, detail, recommendation="", ref=""):
        self.check_id = check_id
        self.title = title
        self.status = status  # "PASS", "FAIL", "WARN", "INFO", "SKIP"
        self.detail = detail
        self.recommendation = recommendation
        self.ref = ref

    def to_dict(self):
        return {
            "id": self.check_id,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "reference": self.ref,
        }


class WPHardeningChecker:
    def __init__(self, base_url, timeout=10):
        parsed = urlparse(base_url)
        if not parsed.scheme:
            base_url = "https://" + base_url
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.results = []

    def _get(self, path="", **kwargs):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=True, allow_redirects=True, **kwargs
            )
        except requests.exceptions.SSLError:
            try:
                return self.session.get(
                    url, timeout=self.timeout, verify=False, allow_redirects=True, **kwargs
                )
            except requests.exceptions.RequestException:
                return None
        except requests.exceptions.RequestException:
            return None

    def add(self, *args, **kwargs):
        self.results.append(Result(*args, **kwargs))

    # ---------- checks ----------

    def check_https(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            self.add(
                "https_scheme", "Situs diakses via HTTPS", "WARN",
                f"URL yang diuji menggunakan '{parsed.scheme}'. Coba paksa https://",
                "Pastikan seluruh situs, terutama /wp-admin/ dan /wp-login.php, hanya bisa diakses via HTTPS.",
                "Securing wp-admin (Administration Over SSL)",
            )
        r = self._get("/wp-login.php")
        if r is None:
            self.add("https_login", "HTTPS pada halaman login", "SKIP", "Tidak dapat menghubungi /wp-login.php")
            return
        if r.url.startswith("https://"):
            self.add(
                "https_login", "HTTPS pada halaman login", "PASS",
                f"Halaman login diarahkan/tersaji via HTTPS ({r.url})",
            )
        else:
            self.add(
                "https_login", "HTTPS pada halaman login", "FAIL",
                f"Halaman login tersaji via HTTP ({r.url}) - kredensial dapat disadap.",
                "Paksa redirect semua traffic wp-login.php dan wp-admin/ ke HTTPS.",
                "Securing wp-admin",
            )
        r2 = self._get("/")
        if r2 is not None:
            hsts = r2.headers.get("Strict-Transport-Security")
            if hsts:
                self.add("hsts", "Header HSTS", "PASS", f"Ditemukan: {hsts}")
            else:
                self.add(
                    "hsts", "Header HSTS", "WARN",
                    "Header Strict-Transport-Security tidak ditemukan.",
                    "Tambahkan header HSTS di web server untuk memaksa HTTPS pada kunjungan berikutnya.",
                )

    def check_admin_ajax_and_wp_admin_exposure(self):
        r = self._get("/wp-admin/")
        if r is None:
            self.add("wp_admin_access", "Proteksi lapis kedua di /wp-admin/", "SKIP", "Tidak dapat menghubungi /wp-admin/")
            return
        if r.status_code == 401:
            self.add(
                "wp_admin_access", "Proteksi lapis kedua di /wp-admin/", "PASS",
                "Menerima HTTP 401 - kemungkinan sudah dilindungi HTTP Basic Auth.",
            )
        elif r.status_code in (301, 302) and "wp-login" in r.headers.get("Location", ""):
            self.add(
                "wp_admin_access", "Proteksi lapis kedua di /wp-admin/", "INFO",
                "Diarahkan ke wp-login.php (perilaku default WordPress, tidak ada proteksi tambahan terdeteksi).",
                "Pertimbangkan menambah HTTP Basic Auth atau pembatasan IP di /wp-admin/ sebagai lapisan kedua.",
                "Securing wp-admin",
            )
        else:
            self.add(
                "wp_admin_access", "Proteksi lapis kedua di /wp-admin/", "WARN",
                f"Status HTTP {r.status_code} saat mengakses /wp-admin/ tanpa autentikasi tambahan.",
                "Tambahkan proteksi lapis kedua (BasicAuth) pada /wp-admin/.",
                "Securing wp-admin",
            )

    def check_wp_includes_protection(self):
        test_paths = [
            "wp-includes/wlwmanifest.xml",
            "wp-includes/js/tinymce/tinymce.min.js",
        ]
        exposed = []
        for p in test_paths:
            r = self._get(p)
            if r is not None and r.status_code == 200:
                exposed.append(p)

        php_test = "wp-includes/registration.php"
        r = self._get(php_test)
        if r is not None and r.status_code == 200 and len(r.content) > 0:
            self.add(
                "wp_includes_php", "Blokir eksekusi file PHP di /wp-includes/", "FAIL",
                f"{php_test} dapat diakses langsung (status {r.status_code}).",
                "Tambahkan rule mod_rewrite untuk memblokir akses langsung ke *.php di wp-includes/ (di luar tag BEGIN/END WordPress).",
                "Securing wp-includes",
            )
        elif r is not None and r.status_code in (403, 404):
            self.add(
                "wp_includes_php", "Blokir eksekusi file PHP di /wp-includes/", "PASS",
                f"{php_test} mengembalikan status {r.status_code} (kemungkinan sudah diblokir atau memang tidak ada).",
            )
        else:
            self.add(
                "wp_includes_php", "Blokir eksekusi file PHP di /wp-includes/", "INFO",
                "Tidak dapat memastikan (respons tidak konklusif).",
            )

    def check_wp_config_exposure(self):
        paths = [
            "wp-config.php",
            "wp-config.php.bak",
            "wp-config.php~",
            "wp-config.old",
            "wp-config.txt",
            ".wp-config.php.swp",
            "wp-config.php.save",
        ]
        exposed = []
        for p in paths:
            r = self._get(p)
            if r is not None and r.status_code == 200 and (
                "DB_PASSWORD" in r.text or "DB_NAME" in r.text
            ):
                exposed.append(p)

        if exposed:
            self.add(
                "wp_config_exposure", "wp-config.php tidak bisa diakses publik", "FAIL",
                f"KRITIS: file berikut tampak bocor berisi kredensial database: {', '.join(exposed)}",
                "Segera blokir akses via .htaccess/nginx config dan rotasi semua kredensial database & secret keys.",
                "Securing wp-config.php",
            )
        else:
            self.add(
                "wp_config_exposure", "wp-config.php tidak bisa diakses publik", "PASS",
                "Tidak ditemukan wp-config.php atau variannya yang bocor secara publik.",
            )

    def check_directory_listing(self):
        dirs = ["wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/", "wp-includes/"]
        issues = []
        for d in dirs:
            r = self._get(d)
            if r is not None and r.status_code == 200 and (
                "Index of /" in r.text or "<title>Index of" in r.text
            ):
                issues.append(d)
        if issues:
            self.add(
                "dir_listing", "Directory listing dinonaktifkan", "FAIL",
                f"Directory listing AKTIF pada: {', '.join(issues)}",
                "Nonaktifkan directory listing (Options -Indexes di Apache, atau autoindex off; di Nginx).",
                "File Permissions",
            )
        else:
            self.add(
                "dir_listing", "Directory listing dinonaktifkan", "PASS",
                "Tidak ditemukan directory listing terbuka pada direktori yang diuji.",
            )

    def check_readme_and_version_disclosure(self):
        version_found = []

        r = self._get("readme.html")
        if r is not None and r.status_code == 200 and "wordpress" in r.text.lower():
            m = re.search(r"Version\s+([\d.]+)", r.text)
            version_found.append(("readme.html", m.group(1) if m else "unknown"))

        r2 = self._get("/")
        if r2 is not None:
            m2 = re.search(r'name="generator"\s+content="WordPress\s+([\d.]+)"', r2.text, re.IGNORECASE)
            if m2:
                version_found.append(("meta generator tag", m2.group(1)))
            m3 = re.search(r"/wp-content/themes/[^/\"']+/style\.css\?ver=([\d.]+)", r2.text)
            if m3:
                version_found.append(("query string aset (?ver=)", m3.group(1)))

        if version_found:
            detail = "; ".join(f"{src}: v{ver}" for src, ver in version_found)
            self.add(
                "version_disclosure", "Versi WordPress tidak terekspos publik", "WARN",
                f"Versi WordPress terdeteksi dari: {detail}",
                "Hapus/kosongkan readme.html, hapus meta generator tag, dan hilangkan parameter versi pada enqueue script/style.",
                "Security through obscurity / Vulnerabilities in WordPress",
            )
        else:
            self.add(
                "version_disclosure", "Versi WordPress tidak terekspos publik", "PASS",
                "Tidak ditemukan indikasi versi WordPress dari readme.html, meta generator, atau query string aset.",
            )

    def check_default_admin_username(self):
        findings = []

        r = self._get("wp-json/wp/v2/users")
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and data:
                    usernames = [u.get("slug", "?") for u in data]
                    findings.append(f"REST API wp-json/wp/v2/users mengekspos slug: {', '.join(usernames)}")
            except ValueError:
                pass

        r2 = self._get("?author=1")
        if r2 is not None and r2.status_code in (301, 302):
            loc = r2.headers.get("Location", "")
            m = re.search(r"/author/([^/]+)/", loc)
            if m:
                findings.append(f"Enumerasi via ?author=1 mengarah ke /author/{m.group(1)}/")

        if findings:
            self.add(
                "user_enum", "Username admin tidak mudah dienumerasi", "WARN",
                " | ".join(findings),
                "Batasi/matikan REST API users endpoint untuk publik (jika tidak perlu) dan blokir enumerasi via ?author=N. Ganti username admin dari nama umum seperti 'admin'.",
                "Security through obscurity",
            )
        else:
            self.add(
                "user_enum", "Username admin tidak mudah dienumerasi", "PASS",
                "Tidak ditemukan kebocoran username melalui REST API users atau enumerasi ?author=.",
            )

    def check_xmlrpc(self):
        r = self._get("xmlrpc.php")
        if r is None:
            self.add("xmlrpc", "xmlrpc.php dibatasi/dinonaktifkan", "SKIP", "Tidak dapat menghubungi xmlrpc.php")
            return
        if r.status_code == 405 or "XML-RPC server accepts POST requests only" in r.text:
            self.add(
                "xmlrpc", "xmlrpc.php dibatasi/dinonaktifkan", "WARN",
                "xmlrpc.php aktif dan merespons normal (berpotensi untuk brute-force pingback / amplification).",
                "Jika tidak dibutuhkan (Jetpack/aplikasi mobile lama), nonaktifkan atau batasi akses xmlrpc.php via firewall/plugin.",
                "Brute Force Attacks (terkait)",
            )
        elif r.status_code in (403, 404):
            self.add(
                "xmlrpc", "xmlrpc.php dibatasi/dinonaktifkan", "PASS",
                f"xmlrpc.php mengembalikan status {r.status_code} (kemungkinan sudah diblokir).",
            )
        else:
            self.add(
                "xmlrpc", "xmlrpc.php dibatasi/dinonaktifkan", "INFO",
                f"Status tidak konklusif: {r.status_code}",
            )

    def check_security_headers(self):
        r = self._get("/")
        if r is None:
            self.add("sec_headers", "Header keamanan HTTP", "SKIP", "Tidak dapat menghubungi situs.")
            return
        headers_to_check = {
            "X-Content-Type-Options": "Mencegah MIME-sniffing",
            "X-Frame-Options": "Mencegah clickjacking (atau gunakan CSP frame-ancestors)",
            "Content-Security-Policy": "Mitigasi XSS/injection konten",
            "Referrer-Policy": "Kontrol kebocoran referrer",
        }
        missing = [h for h in headers_to_check if h not in r.headers]
        present = [h for h in headers_to_check if h in r.headers]

        server_header = r.headers.get("Server", "")
        xpb = r.headers.get("X-Powered-By", "")

        detail_extra = []
        if server_header:
            detail_extra.append(f"Server header: '{server_header}' (idealnya disamarkan/dikosongkan)")
        if xpb:
            detail_extra.append(f"X-Powered-By: '{xpb}' (sebaiknya disembunyikan)")

        status = "PASS" if not missing else ("WARN" if len(missing) < len(headers_to_check) else "FAIL")
        self.add(
            "sec_headers", "Header keamanan HTTP terpasang", status,
            f"Ada: {', '.join(present) or '-'}; Tidak ada: {', '.join(missing) or '-'}. "
            + ("; ".join(detail_extra) if detail_extra else ""),
            "Tambahkan header keamanan yang hilang di web server/plugin, dan sembunyikan header Server/X-Powered-By.",
            "Web Server Vulnerabilities (defense-in-depth)",
        )

    def check_file_editor_disabled(self):
        r = self._get("wp-admin/theme-editor.php")
        if r is None:
            self.add("file_editor", "Editor tema/plugin dari Dashboard", "SKIP", "Tidak dapat menghubungi endpoint.")
            return
        if r.status_code in (301, 302) and "wp-login" in r.headers.get("Location", ""):
            self.add(
                "file_editor", "Editor tema/plugin dari Dashboard", "INFO",
                "Endpoint editor memerlukan login (perilaku normal). Status DISALLOW_FILE_EDIT tidak dapat dipastikan dari luar.",
                "Verifikasi manual: pastikan define('DISALLOW_FILE_EDIT', true); ada di wp-config.php.",
                "Disable File Editing",
            )
        elif r.status_code == 200:
            self.add(
                "file_editor", "Editor tema/plugin dari Dashboard", "WARN",
                "Endpoint editor merespons 200 tanpa redirect ke login - perlu verifikasi manual lebih lanjut.",
                "Periksa langsung apakah editor benar-benar dapat diakses tanpa autentikasi (kemungkinan besar false positive dari cache/WAF).",
                "Disable File Editing",
            )
        else:
            self.add(
                "file_editor", "Editor tema/plugin dari Dashboard", "INFO",
                f"Status: {r.status_code}",
            )

    def check_login_rate_limit_indicator(self):
        r = self._get("/")
        indicators = []
        if r is not None:
            combined = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
            body_lower = r.text[:5000].lower()
            for name, needle in [
                ("Wordfence", "wordfence"),
                ("Sucuri", "sucuri"),
                ("Cloudflare", "cloudflare"),
                ("iThemes/Solid Security", "ithemes"),
            ]:
                if needle in combined or needle in body_lower:
                    indicators.append(name)
        if indicators:
            self.add(
                "brute_force_protection", "Indikasi proteksi brute-force/firewall", "PASS",
                f"Terdeteksi kemungkinan proteksi: {', '.join(indicators)}",
            )
        else:
            self.add(
                "brute_force_protection", "Indikasi proteksi brute-force/firewall", "INFO",
                "Tidak terdeteksi tanda-tanda WAF/plugin keamanan populer dari header/konten publik "
                "(bukan berarti tidak ada - banyak WAF tidak menampilkan signature).",
                "Pastikan ada mekanisme rate-limiting/2FA pada halaman login (lihat: developer.wordpress.org/.../security/brute-force/).",
                "Brute Force Attacks",
            )

    def check_backup_file_exposure(self):
        candidates = [
            "backup.zip", "backup.sql", "backup.tar.gz", "wp-content.zip",
            "database.sql", "db_backup.sql", ".env", "wp-content/backup.zip",
        ]
        exposed = []
        for c in candidates:
            r = self._get(c)
            if r is not None and r.status_code == 200 and len(r.content) > 100:
                exposed.append(c)
        if exposed:
            self.add(
                "backup_exposure", "Tidak ada file backup/sensitif tertinggal di webroot", "FAIL",
                f"File berikut tampak dapat diunduh publik: {', '.join(exposed)}",
                "Hapus segera file tersebut dari webroot dan simpan backup di lokasi yang tidak dapat diakses web.",
                "Data Backups",
            )
        else:
            self.add(
                "backup_exposure", "Tidak ada file backup/sensitif tertinggal di webroot", "PASS",
                "Tidak ditemukan file backup umum yang bocor pada path yang diuji.",
            )

    def check_tls_certificate(self):
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        if not host:
            self.add("tls_cert", "Sertifikat TLS valid", "SKIP", "Host tidak dapat diparse.")
            return
        port = parsed.port or 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    if not not_after:
                        self.add("tls_cert", "Sertifikat TLS valid", "SKIP", "Tidak ada tanggal kedaluwarsa pada sertifikat.")
                        return
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        self.add("tls_cert", "Sertifikat TLS valid", "FAIL", f"Sertifikat SUDAH KEDALUWARSA sejak {expiry.date()}.")
                    elif days_left < 14:
                        self.add("tls_cert", "Sertifikat TLS valid", "WARN", f"Sertifikat akan kedaluwarsa dalam {days_left} hari ({expiry.date()}).")
                    else:
                        self.add("tls_cert", "Sertifikat TLS valid", "PASS", f"Valid, kedaluwarsa {expiry.date()} ({days_left} hari lagi).")
        except Exception as e:
            self.add("tls_cert", "Sertifikat TLS valid", "WARN", f"Tidak dapat memverifikasi sertifikat TLS: {e}")

    # ---------- runner ----------
    def run_all(self):
        checks = [
            self.check_https,
            self.check_tls_certificate,
            self.check_security_headers,
            self.check_admin_ajax_and_wp_admin_exposure,
            self.check_wp_includes_protection,
            self.check_wp_config_exposure,
            self.check_directory_listing,
            self.check_readme_and_version_disclosure,
            self.check_default_admin_username,
            self.check_xmlrpc,
            self.check_file_editor_disabled,
            self.check_login_rate_limit_indicator,
            self.check_backup_file_exposure,
        ]
        for c in checks:
            try:
                c()
            except Exception as e:
                self.add(c.__name__, c.__name__, "SKIP", f"Error internal saat cek: {e}")
        return self.results


# ---------------- report builder ----------------

def build_json_report(url, results, timeout=10):
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {
        "target": url,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": counts,
        "checks": [r.to_dict() for r in results],
        "disclaimer": (
            "Pengecekan ini bersifat eksternal/pasif via HTTP saja. Item terkait "
            "file permission, isi wp-config.php, privilege database, dan konstanta "
            "PHP (mis. DISALLOW_FILE_EDIT) tidak dapat divalidasi penuh tanpa akses "
            "shell/SSH ke server. Gunakan hanya pada situs milik sendiri atau dengan izin eksplisit."
        ),
    }


def run_hardening(base_url, timeout=10):
    """Jalankan seluruh pengecekan hardening secara pasif/eksternal.
    Mengembalikan dict laporan JSON siap disimpan/ditampilkan."""
    checker = WPHardeningChecker(base_url, timeout=timeout)
    results = checker.run_all()
    return build_json_report(checker.base_url, results, timeout=timeout)


# ---------------- CLI (opsional, agar tetap bisa jalan mandiri) ----------------

STATUS_ICON = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "INFO": "ℹ️ ", "SKIP": "⏭️ "}


def print_text_report(url, results):
    print("=" * 78)
    print(" LAPORAN AUDIT HARDENING WORDPRESS (EKSTERNAL)")
    print(f" Target : {url}")
    print(f" Waktu  : {datetime.now().isoformat(timespec='seconds')}")
    print("=" * 78)
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
        print(f"\n{STATUS_ICON.get(r.status, '')} [{r.status}] {r.title}")
        print(f"    Detail : {r.detail}")
        if r.recommendation:
            print(f"    Saran  : {r.recommendation}")
        if r.ref:
            print(f"    Ref    : {r.ref}")
    print("\n" + "-" * 78)
    print("RINGKASAN:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    print("-" * 78)
    print(
        "\nCatatan: Ini adalah pengecekan PASIF dari luar server. Banyak item pada\n"
        "panduan hardening resmi (permission file, privilege DB, isi wp-config.php,\n"
        "DISALLOW_FILE_EDIT, dsb.) TIDAK BISA divalidasi 100% tanpa akses shell/SSH\n"
        "ke server. Hasil WARN/INFO perlu diverifikasi manual."
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Audit hardening WordPress secara eksternal (HTTP-only, tanpa akses shell)."
    )
    parser.add_argument("url", help="URL situs WordPress, mis. https://contoh.com")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Format output")
    parser.add_argument("--output", help="Simpan hasil ke file (opsional)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per request (detik)")
    args = parser.parse_args()

    print(f"Menjalankan pengecekan terhadap {args.url} ...\n", file=sys.stderr)
    report = run_hardening(args.url, timeout=args.timeout)

    if args.format == "json":
        output_str = json.dumps(report, indent=2, ensure_ascii=False)
        print(output_str)
    else:
        checker_results = []
        for c in report["checks"]:
            checker_results.append(Result(
                c["id"], c["title"], c["status"], c["detail"],
                c.get("recommendation", ""), c.get("reference", "")
            ))
        import io
        buf = io.StringIO()
        _stdout = sys.stdout
        sys.stdout = buf
        print_text_report(report["target"], checker_results)
        sys.stdout = _stdout
        print(buf.getvalue())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"\nLaporan disimpan ke: {args.output}", file=sys.stderr)