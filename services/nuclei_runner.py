import os
import json
import time
import asyncio

def empty_result(target_url, status="failed", duration=0.0, raw_output="", stderr=""):
    return {
        "status": status,
        "duration": duration,
        "raw_output": raw_output,
        "stderr": stderr,
        "vuln_count": 0,
        "findings": []
    }

async def run_process_with_log(cmd, timeout=3600, log_callback=None):
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
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


async def run_nuclei(target_url, log_callback=None, cookies=None, headers=None,
                     severity=None, extra_tags=None, headless=False, templates_path=None):
    cmd = [
        "nuclei",
        "-u", target_url,
    ]
    if templates_path:
        cmd += ["-templates", templates_path]
    else:
        tags = ["wordpress"]
        if extra_tags:
            tags += [t.strip() for t in extra_tags.replace(",", " ").split() if t.strip()]
        cmd += ["-tags", ",".join(tags)]
    cmd += ["-severity", severity or "critical,high,medium,low"]
    if headless:
        cmd += ["-headless"]
    if cookies:
        cmd += ["-cookies", cookies]
    for h in (headers or []):
        cmd += ["-H", h]
    cmd += ["-jsonl", "-v"]
    
    start = time.time()
    try:
        raw_output, err_output, returncode = await run_process_with_log(cmd, timeout=900, log_callback=log_callback)
    except asyncio.TimeoutError:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=time.time() - start,
            raw_output="Nuclei timeout",
            stderr="Proses scan melebihi batas waktu"
        )
    except FileNotFoundError:
        return empty_result(
            target_url=target_url,
            status="failed",
            raw_output="Perintah 'nuclei' tidak ditemukan. Pastikan Nuclei sudah terinstall."
        )

    duration = time.time() - start

    if returncode != 0 and not raw_output:
        return empty_result(
            target_url=target_url,
            status="failed",
            duration=duration,
            raw_output=err_output or "Nuclei tidak mengembalikan output.",
            stderr=err_output
        )

    findings = []
    lines = raw_output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            cve_ids = classification.get("cve-id", []) or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
                
            findings.append({
                "template_id": data.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "description": info.get("description"),
                "remediation": info.get("remediation"),
                "cve_ids": cve_ids,
                "matched_at": data.get("matched-at")
            })
        except json.JSONDecodeError:
            pass

    if not raw_output and process.returncode == 0:
        raw_output = "Scan selesai. Tidak ada kerentanan terdeteksi oleh Nuclei."

    return {
        "status": "scanned",
        "duration": duration,
        "raw_output": raw_output,
        "stderr": err_output,
        "vuln_count": len(findings),
        "findings": findings
    }
