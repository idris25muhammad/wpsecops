import json
import re
import time
import asyncio


async def run_whatweb(target_url, log_callback=None):
    """
    Run WhatWeb in aggressive mode to identify technologies on the target.
    Output: JSON array via --log-json=-
    
    Detected info: CMS/WordPress version, server, PHP, JS libs, email, IP, etc.
    """
    cmd = [
        "whatweb",
        "--log-json=-",         # JSON output to stdout
        "-a", "3",              # aggressive mode: more requests, richer results
        "--no-errors",          # suppress connection errors to keep output clean
        target_url
    ]

    start = time.time()

    if log_callback:
        await log_callback(f"Menjalankan: whatweb --log-json=- -a 3 {target_url}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError:
        return {
            "status": "failed",
            "duration": 0.0,
            "raw_output": "Perintah 'whatweb' tidak ditemukan. Pastikan WhatWeb sudah terinstall (gem install whatweb atau apt install whatweb).",
            "tech_stack": {},
            "target_info": {}
        }

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
            timeout=120
        )
        await process.wait()
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "status": "failed",
            "duration": time.time() - start,
            "raw_output": "WhatWeb timeout (120s)",
            "tech_stack": {},
            "target_info": {}
        }

    duration = time.time() - start
    raw_output = "".join(stdout_chunks).strip()

    if not raw_output:
        return {
            "status": "failed",
            "duration": duration,
            "raw_output": "WhatWeb tidak mengembalikan output.",
            "tech_stack": {},
            "target_info": {}
        }

    # Parse WhatWeb output tolerantly:
    # - prefer JSON (--log-json=-)
    # - tolerate interleaved summary + JSON, atau format teks berwarna
    #   (beberapa versi WhatWeb tidak mengeluarkan JSON walau --log-json=- dipakai)
    tech_stack = {}
    target_info = {
        "wordpress_version": None,
        "server": None,
        "php_version": None,
        "ip_address": None,
        "technologies": []
    }

    data_list = []
    text = re.sub(r"\x1b\[[0-9;]*m", "", raw_output).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            data_list = parsed
        elif isinstance(parsed, dict):
            data_list = [parsed]
    except (json.JSONDecodeError, ValueError):
        # Cari blok JSON array di dalam teks (mis. ada summary di depannya)
        for marker in ('[{"target"', '[ {', '[{'):
            idx = text.find(marker)
            if idx != -1:
                end = text.rfind("]")
                if end > idx:
                    try:
                        parsed = json.loads(text[idx:end + 1])
                        if isinstance(parsed, list):
                            data_list = parsed
                            break
                    except (json.JSONDecodeError, ValueError):
                        pass
        if not data_list:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, list):
                        data_list.extend(obj)
                    elif isinstance(obj, dict):
                        data_list.append(obj)
                except (json.JSONDecodeError, ValueError):
                    continue

    if not data_list:
        # Fallback: format teks ringkas WhatWeb, mis:
        #   http://... [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], PHP[7.2.32], ...
        for name, value in re.findall(r"([A-Za-z][A-Za-z0-9_]*)\[([^\]]*)\]", text):
            if name.lower().startswith("http"):
                continue
            tech_stack.setdefault(name, None)
            if value and tech_stack[name] is None:
                tech_stack[name] = value
            target_info["technologies"].append(
                f"{name}{': ' + value if value else ''}"
            )

            tech_lower = name.lower()
            if "wordpress" in tech_lower or (value and "WordPress" in value):
                m = re.search(r"WordPress\s+([\d.]+)", value)
                if m and not target_info["wordpress_version"]:
                    target_info["wordpress_version"] = m.group(1)
            elif tech_lower in ("apache", "nginx", "iis", "litespeed") and value:
                if not target_info["server"]:
                    target_info["server"] = f"{name} {value}"
            elif tech_lower == "php" and value:
                if not target_info["php_version"]:
                    target_info["php_version"] = value
            elif tech_lower == "ip" and value:
                if not target_info["ip_address"]:
                    target_info["ip_address"] = value

    for entry in data_list:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins", {}) or {}

        for tech_name, tech_data in plugins.items():
            if not isinstance(tech_data, dict):
                continue

            versions = tech_data.get("string", []) or []
            version = versions[0] if versions else None
            tech_stack[tech_name] = version
            target_info["technologies"].append(
                f"{tech_name}{': ' + version if version else ''}"
            )

            # Extract specific fields
            tech_lower = tech_name.lower()
            if "wordpress" in tech_lower and version:
                target_info["wordpress_version"] = version
            elif tech_lower in ("apache", "nginx", "iis", "litespeed") and version:
                target_info["server"] = f"{tech_name} {version}"
            elif tech_lower == "php" and version:
                target_info["php_version"] = version

        # IP address
        ip = entry.get("plugins", {}).get("IP", {})
        if isinstance(ip, dict):
            ips = ip.get("string", [])
            if ips:
                target_info["ip_address"] = ips[0]

    if log_callback:
        tech_count = len(tech_stack)
        wp_ver = target_info.get("wordpress_version")
        await log_callback(
            f"WhatWeb selesai: {tech_count} teknologi teridentifikasi"
            f"{', WordPress v' + wp_ver if wp_ver else ''}"
        )

    return {
        "status": "scanned" if tech_stack else "failed",
        "duration": duration,
        "raw_output": raw_output,
        "tech_stack": tech_stack,
        "target_info": target_info
    }
