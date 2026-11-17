import os
import json
import asyncio
import time
import uuid
from celery import Celery
from dotenv import load_dotenv
from models import db, ScanHistory, ScanResult
from services.whatweb_runner import run_whatweb
from services.wpscan_runner import run_wpscan
from services.nuclei_runner import run_nuclei
from services.hardening_runner import run_hardening

load_dotenv()

celery_app = Celery(
    "tasks",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
)
celery_app.conf.update(
    task_always_eager=os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ("true", "1", "yes")
)


class ThrottledLogWriter:
    def __init__(self, history_id, scanner_type, app):
        self.history_id = history_id
        self.scanner_type = scanner_type
        self.app = app
        self.buffer = []
        self.last_write = 0.0
        self._lock = asyncio.Lock()

    async def write(self, line_text):
        if not line_text:
            return
        async with self._lock:
            self.buffer.append(line_text)
            now = time.time()
            if now - self.last_write > 0.6 or len(self.buffer) >= 3:
                await self._flush_unlocked()

    async def flush(self):
        async with self._lock:
            await self._flush_unlocked()

    async def _flush_unlocked(self):
        if not self.buffer:
            return
        lines_to_write = "\n".join(self.buffer)
        self.buffer.clear()
        self.last_write = time.time()
        with self.app.app_context():
            db_res = ScanResult.query.filter_by(
                scan_history_id=self.history_id,
                scanner_type=self.scanner_type
            ).first()
            if db_res:
                if db_res.raw_output:
                    db_res.raw_output += "\n" + lines_to_write
                else:
                    db_res.raw_output = lines_to_write
                db.session.commit()


def parse_wpscan_components(raw_output):
    """Parse WPScan JSON (no-API mode) → component list + enriched target_info."""
    components = []
    target_info = {
        "wordpress_version": None,
        "main_theme": None,
        "plugins_detected": [],
        "users_detected": [],
        "interesting_findings": []
    }
    try:
        data = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError):
        try:
            idx = raw_output.find("{")
            if idx != -1:
                data = json.loads(raw_output[idx:])
            else:
                return components, target_info
        except Exception:
            return components, target_info

    if not isinstance(data, dict) or "scan_aborted" in data:
        return components, target_info

    version_data = data.get("version", {}) or {}
    main_theme = data.get("main_theme", {}) or {}
    plugins = data.get("plugins", {}) or {}
    users = data.get("users", {}) or {}
    interesting = data.get("interesting_findings", []) or []

    if version_data.get("number"):
        target_info["wordpress_version"] = version_data["number"]

    if main_theme.get("slug"):
        target_info["main_theme"] = main_theme.get("friendly_name") or main_theme.get("slug")
        components.append({
            "component_type": "theme",
            "component_name": main_theme.get("slug"),
            "version": main_theme.get("version", {}).get("number") if isinstance(main_theme.get("version"), dict) else None,
            "source": "wpscan",
        })

    if isinstance(plugins, dict):
        for slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict) or slug == "*":
                continue
            version_obj = plugin_data.get("version")
            plugin_version = version_obj.get("number") if isinstance(version_obj, dict) else None
            target_info["plugins_detected"].append(slug)
            components.append({
                "component_type": "plugin",
                "component_name": slug,
                "version": plugin_version,
                "source": "wpscan",
                "outdated": plugin_data.get("outdated", False),
                "latest_version": plugin_data.get("latest_version"),
            })

    if isinstance(users, dict):
        for username in users.keys():
            target_info["users_detected"].append(username)

    target_info["interesting_findings"] = interesting
    return components, target_info


def parse_nuclei_findings(raw_output):
    """Parse nuclei JSONL output into a list of finding dicts."""
    findings = []
    for line in (raw_output or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "template-id" not in item:
            continue
        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        findings.append({
            "template_id": item.get("template-id", ""),
            "name": info.get("name", "Nuclei Finding"),
            "severity": (info.get("severity") or "medium").lower(),
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "tags": info.get("tags", []) or [],
            "cve_ids": cve_ids,
            "matched_at": item.get("matched-at", ""),
            "matcher_name": item.get("matcher-name", ""),
        })
    return findings


def assign_confidence(nuclei_finding, wpscan_components):
    """
    Cross-match a Nuclei finding against WPScan component list.
    - Component match in WPScan → Confirmed
    - No WPScan match → Likely
    """
    template_id = (nuclei_finding.get("template_id") or "").lower()
    name = (nuclei_finding.get("name") or "").lower()
    for comp in wpscan_components:
        comp_name = (comp.get("component_name") or "").lower()
        if comp_name and (comp_name in template_id or comp_name in name):
            return "Confirmed", comp
    return "Likely", None


@celery_app.task(bind=True)
def scan_task(self, history_id, target_url, api_token=None, plugins_detection="aggressive", scanners=None, scan_params=None):
    from app import app
    from models import ScanFinding

    scan_params = scan_params or {}
    
    # Ambil mode eksekusi dari scan_params, default ke "parallel"
    execution_mode = scan_params.get("execution_mode", "parallel")

    ALL_SCANNERS = ["whatweb", "wpscan", "nuclei", "hardening"]
    if not scanners:
        scanners = ALL_SCANNERS
    else:
        scanners = [s for s in ALL_SCANNERS if s in scanners]
    if not scanners:
        scanners = ALL_SCANNERS

    with app.app_context():
        history = db.session.get(ScanHistory, history_id)
        if not history:
            return {"status": "failed", "message": f"ScanHistory {history_id} tidak ditemukan"}

        ScanResult.query.filter_by(scan_history_id=history.id).delete()
        ScanFinding.query.filter_by(scan_history_id=history.id).delete()

        for s in scanners:
            db.session.add(ScanResult(
                scan_history_id=history.id,
                scanner_type=s,
                status="pending",
                vuln_count=0,
                raw_output=""
            ))
        history.status = "scanning"
        db.session.commit()

    whatweb_writer = ThrottledLogWriter(history_id, "whatweb", app)
    wpscan_writer = ThrottledLogWriter(history_id, "wpscan", app)
    nuclei_writer = ThrottledLogWriter(history_id, "nuclei", app)
    hardening_writer = ThrottledLogWriter(history_id, "hardening", app)

    async def run_pipeline():
        start_time = time.time()

        whatweb_res = {}
        wpscan_res = {}
        nuclei_res = {}
        hardening_res = {}

        # Fungsi helper untuk masing-masing scanner
        async def execute_whatweb():
            if "whatweb" not in scanners:
                return
            await whatweb_writer.write("━━━ FASE: WhatWeb Technology Identification ━━━")
            await whatweb_writer.write(f"[WHATWEB] Target: {target_url}")
            
            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="whatweb").first()
                if res:
                    res.status = "scanning"
                    db.session.commit()

            w_start = time.time()
            nonlocal whatweb_res
            whatweb_res = await run_whatweb(target_url, log_callback=lambda line: whatweb_writer.write(f"[WHATWEB] {line}"))
            await whatweb_writer.flush()
            w_duration = time.time() - w_start

            tech_stack = whatweb_res.get("tech_stack", {})
            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="whatweb").first()
                if res:
                    res.status = whatweb_res.get("status", "failed")
                    res.raw_output = whatweb_res.get("raw_output", "")
                    res.duration = w_duration
                    res.vuln_count = 0
                    db.session.commit()

            await whatweb_writer.write(f"[WHATWEB] Selesai {w_duration:.1f}s - {len(tech_stack)} teknologi teridentifikasi")
            await whatweb_writer.flush()

        async def execute_wpscan():
            if "wpscan" not in scanners:
                return
            await wpscan_writer.write("━━━ FASE: WPScan WordPress Fingerprinting & Enumeration ━━━")
            await wpscan_writer.write(f"[WPSCAN] Target: {target_url}")

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="wpscan").first()
                if res:
                    res.status = "scanning"
                    db.session.commit()

            w_start = time.time()
            nonlocal wpscan_res
            wpscan_res = await run_wpscan(
                target_url,
                api_token=None,
                plugins_detection=plugins_detection,
                log_callback=lambda line: wpscan_writer.write(f"[WPSCAN] {line}"),
                cookies=scan_params.get("cookies"),
                headers=scan_params.get("headers") or [],
            )
            await wpscan_writer.flush()
            w_duration = time.time() - w_start

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="wpscan").first()
                if res:
                    res.status = wpscan_res.get("status", "failed")
                    res.raw_output = wpscan_res.get("raw_output", "")
                    res.duration = w_duration
                    res.vuln_count = 0
                    db.session.commit()

            await wpscan_writer.write(f"[WPSCAN] Selesai {w_duration:.1f}s")
            await wpscan_writer.flush()

        async def execute_nuclei():
            if "nuclei" not in scanners:
                return
            await nuclei_writer.write("━━━ FASE: Nuclei WordPress Exposure Detection ━━━")
            await nuclei_writer.write(f"[NUCLEI] Target: {target_url}")

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="nuclei").first()
                if res:
                    res.status = "scanning"
                    db.session.commit()

            n_start = time.time()
            nonlocal nuclei_res
            nuclei_res = await run_nuclei(
                target_url,
                log_callback=lambda line: nuclei_writer.write(f"[NUCLEI] {line}"),
                cookies=scan_params.get("cookies"),
                headers=scan_params.get("headers") or [],
                severity=scan_params.get("nuclei_severity"),
                extra_tags=scan_params.get("nuclei_tags"),
                headless=bool(scan_params.get("nuclei_headless")),
            )
            await nuclei_writer.flush()
            n_duration = time.time() - n_start
            findings = parse_nuclei_findings(nuclei_res.get("raw_output", ""))

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="nuclei").first()
                if res:
                    res.status = nuclei_res.get("status", "failed")
                    res.raw_output = nuclei_res.get("raw_output", "")
                    res.duration = n_duration
                    res.vuln_count = len(findings)
                    db.session.commit()

            await nuclei_writer.write(f"[NUCLEI] Selesai {n_duration:.1f}s - {len(findings)} eksposur terdeteksi")
            await nuclei_writer.flush()

        async def execute_hardening():
            if "hardening" not in scanners:
                return
            await hardening_writer.write("━━━ FASE: WordPress Hardening Check (Eksternal) ━━━")
            await hardening_writer.write(f"[HARDENING] Target: {target_url}")

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="hardening").first()
                if res:
                    res.status = "scanning"
                    db.session.commit()

            h_start = time.time()
            nonlocal hardening_res
            hardening_res = await asyncio.to_thread(run_hardening, target_url)
            await hardening_writer.flush()
            h_duration = time.time() - h_start
            
            h_raw = json.dumps(hardening_res, ensure_ascii=False)
            fail_count = hardening_res.get("summary", {}).get("FAIL", 0)

            with app.app_context():
                res = ScanResult.query.filter_by(scan_history_id=history_id, scanner_type="hardening").first()
                if res:
                    res.status = "scanned"
                    res.raw_output = h_raw
                    res.duration = h_duration
                    res.vuln_count = fail_count
                    db.session.commit()

            await hardening_writer.write(f"[HARDENING] Selesai {h_duration:.1f}s - FAIL: {fail_count}")
            await hardening_writer.flush()

        # CABANG EKSEKUSI: BERDASARKAN MODE (PARALLEL VS SEQUENTIAL)
        if execution_mode == "sequential":
            # Dijalankan beruntun satu per satu
            await execute_whatweb()
            await execute_wpscan()
            await execute_nuclei()
            await execute_hardening()
        else:
            # Dijalankan bersamaan (Paralel) menggunakan asyncio.gather
            tasks_to_run = [
                execute_whatweb(),
                execute_wpscan(),
                execute_nuclei(),
                execute_hardening()
            ]
            await asyncio.gather(*(t for t in tasks_to_run if t is not None))

        # ─────────────────────────────────────────────────────────────────────
        # FASE POST-PROCESSING: Parsing & Confidence Merging
        # ─────────────────────────────────────────────────────────────────────
        await nuclei_writer.write(f"[SYSTEM] Pipeline {execution_mode} selesai! Memproses hasil...")

        tech_stack = whatweb_res.get("tech_stack", {})
        whatweb_target_info = whatweb_res.get("target_info", {})
        
        wpscan_raw = wpscan_res.get("raw_output", "")
        wpscan_components, wpscan_target_info = parse_wpscan_components(wpscan_raw)
        wp_version = wpscan_target_info.get("wordpress_version") or whatweb_target_info.get("wordpress_version")
        
        nuclei_raw = nuclei_res.get("raw_output", "")
        nuclei_findings = parse_nuclei_findings(nuclei_raw)

        with app.app_context():
            history_db = db.session.get(ScanHistory, history_id)
            total_findings = 0

            if history_db and wpscan_raw:
                history_db.raw_output = wpscan_raw

            for nf in nuclei_findings:
                confidence, matched_comp = assign_confidence(nf, wpscan_components)

                evidence_parts = [
                    f"Nuclei template '{nf['template_id']}' mendeteksi eksposur aktif.",
                    f"URL cocok: {nf['matched_at'] or target_url}",
                    f"Severity: {nf['severity'].upper()}",
                ]
                if nf["cve_ids"]:
                    evidence_parts.append(f"CVE: {', '.join(nf['cve_ids'])}")

                tech_list = list(tech_stack.keys())
                if tech_list:
                    evidence_parts.append(
                        f"WhatWeb mengidentifikasi stack: {', '.join(tech_list[:8])}"
                        + (" ..." if len(tech_list) > 8 else "")
                    )

                if matched_comp:
                    evidence_parts.append(
                        f"WPScan mengkonfirmasi komponen '{matched_comp['component_name']}' "
                        f"v{matched_comp['version'] or '?'} aktif di target."
                    )
                else:
                    evidence_parts.append("WPScan tidak mendeteksi komponen terkait secara eksplisit.")

                evidence_summary = "\n".join(evidence_parts)
                comp_name = matched_comp["component_name"] if matched_comp else nf["template_id"]
                comp_type = matched_comp["component_type"] if matched_comp else "wordpress"
                comp_ver = matched_comp["version"] if matched_comp else (wp_version or "Tidak diketahui")

                prompt_template = f"""Analisis temuan keamanan berikut pada target WordPress:
- Komponen: {comp_name} ({comp_type})
- Versi: {comp_ver}
- Template Nuclei: {nf['template_id']}
- Severity: {nf['severity'].upper()}
- Confidence: {confidence}
- CVE: {', '.join(nf['cve_ids']) if nf['cve_ids'] else 'Tidak ada'}
- Deskripsi: {nf['description'] or '-'}
- Tech Stack (WhatWeb): {', '.join(list(tech_stack.keys())[:6]) or '-'}
- Bukti:
{evidence_summary}

Berikan langkah mitigasi konkret untuk administrator WordPress."""

                db.session.add(ScanFinding(
                    id=str(uuid.uuid4()),
                    scan_history_id=history_id,
                    component=comp_type,
                    component_name=comp_name,
                    version=comp_ver,
                    cve_id=nf["cve_ids"][0] if nf["cve_ids"] else None,
                    title=f"{nf['name']} - {nf['template_id']}",
                    confidence=confidence,
                    evidence_summary=evidence_summary,
                    ai_prompt_template=prompt_template,
                    ai_response=None,
                    manual_note=None
                ))
                total_findings += 1

            for comp in wpscan_components:
                comp_name_lower = (comp["component_name"] or "").lower()
                already_covered = any(
                    comp_name_lower in (nf.get("template_id") or "").lower() or
                    comp_name_lower in (nf.get("name") or "").lower()
                    for nf in nuclei_findings
                )
                if not already_covered:
                    outdated_note = ""
                    if comp.get("outdated"):
                        outdated_note = f"\nWPScan mendeteksi versi ini OUTDATED (latest: {comp.get('latest_version', '?')})."

                    evidence_summary = (
                        f"WPScan mendeteksi '{comp['component_name']}' v{comp['version'] or '?'} aktif di target.{outdated_note}\n"
                        "Nuclei tidak menemukan eksposur aktif - versi mungkin sudah dipatch atau tidak ada template yang cocok."
                    )
                    prompt_template = f"""Analisis komponen WordPress berikut:
- Komponen: {comp['component_name']} ({comp['component_type']})
- Versi: {comp['version'] or 'Tidak diketahui'}
- Sumber: WPScan Enumeration (No-API)
- Status: Unconfirmed (tidak ada eksposur aktif dari Nuclei)

Apakah versi ini memiliki kerentanan yang diketahui? Berikan rekomendasi keamanan."""

                    db.session.add(ScanFinding(
                        id=str(uuid.uuid4()),
                        scan_history_id=history_id,
                        component=comp["component_type"],
                        component_name=comp["component_name"],
                        version=comp["version"],
                        cve_id=None,
                        title=f"{comp['component_name']} - Terdeteksi WPScan",
                        confidence="Unconfirmed",
                        evidence_summary=evidence_summary,
                        ai_prompt_template=prompt_template,
                        ai_response=None,
                        manual_note=None
                    ))
                    total_findings += 1

            if history_db:
                history_db.vuln_count = total_findings
                history_db.duration = time.time() - start_time
                history_db.status = "scanned"
                db.session.commit()

        await nuclei_writer.write(
            f"[SYSTEM] ✓ Pipeline ({execution_mode}) selesai! Total ScanFinding: {total_findings}"
        )
        await nuclei_writer.flush()
        return "scanned", "success"

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        status, msg = loop.run_until_complete(run_pipeline())
    except Exception as e:
        status = "failed"
        with app.app_context():
            history_db = db.session.get(ScanHistory, history_id)
            if history_db:
                history_db.status = "failed"
                db.session.commit()
    finally:
        loop.close()

    return {
        "status": status,
        "history_id": history_id,
        "scanners": scanners,
        "execution_mode": execution_mode
    }