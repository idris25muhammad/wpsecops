import os
import json
import time
import asyncio
from dotenv import load_dotenv

load_dotenv()


def empty_result(target_url, status="failed", duration=0.0, raw_output="", stderr=""):
    return {
        "status": status,
        "duration": duration,
        "raw_output": raw_output,
        "stderr": stderr,
        "vuln_count": 0,
        "interesting_count": 0,
        "detail": {
            "core_vulns": 0,
            "theme_vulns": 0,
            "plugin_vulns": 0
        },
        "target_info": {
            "url": target_url,
            "wordpress_version": None,
            "main_theme": None,
            "plugins_detected": [],
            "users_detected": []
        },
        "plugin_details": [],
        "users_detected": [],
        "interesting_findings": []
    }


async def run_process_with_log(cmd, timeout=600, log_callback=None, env=None):
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
    except FileNotFoundError:
        raise FileNotFoundError()

    stdout_chunks = []
    stderr_chunks = []

    async def read_stream(stream, chunks_list):
        buffer = ""
        while True:
            chunk = await stream.read(256)
            if not chunk:
                break
            decoded = chunk.decode(errors="ignore")
            chunks_list.append(decoded)
            if log_callback:
                buffer += decoded.replace("\r", "\n")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    txt = line.strip()
                    if txt and not txt.startswith("{") and not txt.startswith("}"):
                        await log_callback(txt)
        if log_callback and buffer.strip():
            txt = buffer.strip()
            if not txt.startswith("{") and not txt.startswith("}"):
                await log_callback(txt)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(process.stdout, stdout_chunks),
                read_stream(process.stderr, stderr_chunks)
            ),
            timeout=timeout
        )
        await process.wait()
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise asyncio.TimeoutError()

    raw_output = "".join(stdout_chunks).strip()
    err_output = "".join(stderr_chunks).strip()
    return raw_output, err_output, process.returncode


async def run_wpscan(target_url, api_token=None, plugins_detection="passive", log_callback=None, cookies=None, headers=None):
    """
    WPScan in fast enumeration-only mode - NO API token required.
    Uses HTTP probing for: vulnerable/popular plugins (vp), vulnerable themes (vt), users (u), timthumbs (tt), config backups (cb).
    Fast completion (~15-45s) avoiding 15,000+ brute-force plugin HTTP requests.
    """
    cmd = [
        "wpscan",
        "--url", target_url,
        "--format", "json",
        "--enumerate", "vp,vt,u,tt,cb",  # vulnerable plugins, vulnerable themes, users, timthumbs, config backups
        "--plugins-detection", plugins_detection or "passive",
        "--max-threads", "10",
        "--disable-tls-checks",
        "--no-update"                   # skip update check for fast speed
    ]
    if cookies:
        cmd += ["--cookie", cookies]
    for h in (headers or []):
        cmd += ["--headers", h]
    # Deliberately NOT adding --api-token - avoids quota entirely.
    # WPScan also auto-reads the WPSCAN_API_TOKEN environment variable (checked
    # via ENV.key?, so even an empty string triggers the API and can abort with
    # "Your API limit has been reached"). Strip it from the child environment to
    # stay in pure HTTP-probing (No-API) mode.
    child_env = dict(os.environ)
    child_env.pop("WPSCAN_API_TOKEN", None)
    child_env.pop("WPSCAN_ENTERPRISE_DB_TOKEN", None)

    start = time.time()

    if log_callback:
        await log_callback(f"Memulai WPScan: wpscan --url {target_url} --enumerate vp,vt,u,tt,cb --plugins-detection {plugins_detection or 'passive'}")

    try:
        raw_output, err_output, returncode = await run_process_with_log(cmd, timeout=600, log_callback=log_callback, env=child_env)
    except asyncio.TimeoutError:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=time.time() - start,
            raw_output="WPScan timeout",
            stderr="Proses scan melebihi batas waktu"
        )
    except FileNotFoundError:
        return empty_result(
            target_url=target_url,
            status="failed",
            raw_output="Perintah 'wpscan' tidak ditemukan. Pastikan WPScan sudah terinstall."
        )

    duration = time.time() - start

    if not raw_output:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=duration,
            raw_output=err_output or "WPScan tidak mengembalikan output.",
            stderr=err_output
        )

    # WPScan with --verbose may emit non-JSON banner lines before the JSON blob
    data = None
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        json_start = raw_output.find("{")
        if json_start != -1:
            try:
                data = json.loads(raw_output[json_start:])
            except json.JSONDecodeError:
                pass

    if data is None:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=duration,
            raw_output=raw_output,
            stderr=err_output
        )

    # Guard: scan_aborted shouldn't happen without API token, but handle gracefully
    if isinstance(data, dict) and "scan_aborted" in data:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=duration,
            raw_output=raw_output,
            stderr=str(data.get("scan_aborted", "Scan aborted"))
        )

    version_data = data.get("version", {}) or {}
    main_theme = data.get("main_theme", {}) or {}
    plugins = data.get("plugins", {}) or {}
    users = data.get("users", {}) or {}
    interesting_findings = data.get("interesting_findings", []) or []

    plugins_detected = []
    plugin_details = []
    users_detected = []

    if isinstance(plugins, dict):
        for slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict) or slug == "*":
                continue
            version_obj = plugin_data.get("version")
            plugin_version = version_obj.get("number") if isinstance(version_obj, dict) else None
            plugins_detected.append(slug)
            plugin_details.append({
                "slug": slug,
                "version": plugin_version,
                "latest_version": plugin_data.get("latest_version"),
                "outdated": plugin_data.get("outdated", False),
            })

    if isinstance(users, dict):
        for username in users.keys():
            users_detected.append(username)

    scan_status = "scanned"
    if returncode != 0:
        has_useful_data = bool(version_data or main_theme or plugins_detected or interesting_findings)
        if not has_useful_data:
            scan_status = "failed"

    return {
        "status": scan_status,
        "duration": duration,
        "raw_output": raw_output,
        "stderr": err_output,
        "vuln_count": 0,                # No CVE data without API - Nuclei handles this
        "interesting_count": len(interesting_findings),
        "detail": {"core_vulns": 0, "theme_vulns": 0, "plugin_vulns": 0},
        "target_info": {
            "url": data.get("target_url", target_url),
            "wordpress_version": version_data.get("number"),
            "main_theme": main_theme.get("friendly_name") or main_theme.get("slug"),
            "plugins_detected": plugins_detected,
            "users_detected": users_detected
        },
        "plugin_details": plugin_details,
        "users_detected": users_detected,
        "interesting_findings": interesting_findings,
    }
