import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import redis as redis_lib
from celery import shared_task
from flask import current_app

from extensions import db
from models import ScanFinding, ScanHistory, ScanResult
from services.correlation import assign_confidence
from services.prompts import build_remediation_prompt
from services.registry import PHASE_ORDER, SCANNERS
from services.vuln_analyzer import build_prompt_for_finding, call_llm_text, compute_ai_cache_key

logger = logging.getLogger("wpsecops.tasks")

if os.getenv("WPSECOPS_SKIP_CREATE_APP") != "1":
    from app import app as _flask_app
    celery_app = _flask_app.extensions["celery"]
else:
    celery_app = None


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_redis_client():
    if current_app.config.get("CELERY_TASK_ALWAYS_EAGER"):
        return None
    url = current_app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    try:
        client = redis_lib.from_url(url, socket_connect_timeout=0.4, socket_timeout=0.4, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


class LiveLogWriter:
    """Buffer log lines in memory for DB persistence and push to Redis for live polling."""

    def __init__(self, history_id, scanner_type, redis_client=None):
        self.history_id = history_id
        self.scanner_type = scanner_type
        self.redis = redis_client
        self.redis_key = f"scan:{history_id}:log:{scanner_type}"
        self.lines = []

    async def write(self, line_text):
        if not line_text:
            return
        self.lines.append(line_text)
        if self.redis is not None:
            try:
                self.redis.rpush(self.redis_key, line_text)
                self.redis.expire(self.redis_key, 86400)
            except Exception:
                self.redis = None

    def get_text(self):
        return "\n".join(self.lines)


def get_live_logs(history_id, scanner_type, since=0, tail=50):
    """Read live logs from Redis if available, returning (lines, next_offset)."""
    client = _get_redis_client()
    if client is None:
        return [], since
    key = f"scan:{history_id}:log:{scanner_type}"
    try:
        total = client.llen(key)
        start = max(since, max(0, total - tail)) if since == 0 else since
        if start >= total:
            return [], total
        items = client.lrange(key, start, -1)
        return items, total
    except Exception:
        return [], since


def _compute_risk_color(vuln_count, max_severity):
    if vuln_count == 0:
        return "green"
    if vuln_count >= 5 or (max_severity or "").lower() in ("critical", "high"):
        return "red"
    return "yellow"


@shared_task(bind=True)
def scan_task(self, history_id, target_url, api_token=None, plugins_detection="passive", scanners=None, scan_params=None):
    scan_params = scan_params or {}
    execution_mode = scan_params.get("execution_mode", "parallel")

    if not scanners:
        selected_scanners = list(PHASE_ORDER)
    else:
        selected_scanners = [s for s in PHASE_ORDER if s in scanners]
    if not selected_scanners:
        selected_scanners = list(PHASE_ORDER)

    history = db.session.get(ScanHistory, history_id)
    if not history:
        return {"status": "failed", "message": f"ScanHistory {history_id} tidak ditemukan"}

    ScanResult.query.filter_by(scan_history_id=history.id).delete()
    ScanFinding.query.filter_by(scan_history_id=history.id).delete()

    for s in selected_scanners:
        db.session.add(ScanResult(
            scan_history_id=history.id,
            scanner_type=s,
            status="pending",
            vuln_count=0,
            raw_output="",
            log_text="",
        ))
    history.status = "scanning"
    db.session.commit()

    redis_client = _get_redis_client()
    writers = {s: LiveLogWriter(history_id, s, redis_client) for s in selected_scanners}

    async def run_pipeline():
        start_time = time.time()
        results_by_scanner = {}
        parsed_by_scanner = {}

        async def execute_scanner(scanner_name):
            spec = SCANNERS[scanner_name]
            writer = writers[scanner_name]
            await writer.write(f"━━━ {spec.label}: {spec.desc} ━━━")
            await writer.write(f"[{scanner_name.upper()}] Target: {target_url}")

            started_at = _utcnow()
            res_row = ScanResult.query.filter_by(
                scan_history_id=history_id, scanner_type=scanner_name
            ).first()
            if res_row:
                res_row.status = "scanning"
                res_row.started_at = started_at
                db.session.commit()

            t0 = time.time()
            if scanner_name == "whatweb":
                res = await spec.runner(
                    target_url,
                    log_callback=lambda line: writer.write(f"[WHATWEB] {line}"),
                )
                raw_out = res.get("raw_output", "")
            elif scanner_name == "wpscan":
                res = await spec.runner(
                    target_url,
                    api_token=None,
                    plugins_detection=plugins_detection,
                    log_callback=lambda line: writer.write(f"[WPSCAN] {line}"),
                    cookies=scan_params.get("cookies"),
                    headers=scan_params.get("headers") or [],
                )
                raw_out = res.get("raw_output", "")
            elif scanner_name == "nuclei":
                res = await spec.runner(
                    target_url,
                    log_callback=lambda line: writer.write(f"[NUCLEI] {line}"),
                    cookies=scan_params.get("cookies"),
                    headers=scan_params.get("headers") or [],
                    severity=scan_params.get("nuclei_severity"),
                    extra_tags=scan_params.get("nuclei_tags"),
                    headless=bool(scan_params.get("nuclei_headless")),
                )
                raw_out = res.get("raw_output", "")
            elif scanner_name == "hardening":
                res = await asyncio.to_thread(spec.runner, target_url)
                raw_out = json.dumps(res, ensure_ascii=False)
            else:
                res = {"status": "failed", "raw_output": ""}
                raw_out = ""

            duration = time.time() - t0
            finished_at = _utcnow()
            parsed = spec.parser(raw_out)
            vuln_count = spec.vuln_counter(res, parsed)
            status = res.get("status", "scanned" if not spec.is_async else "failed")

            await writer.write(f"[{scanner_name.upper()}] Selesai {duration:.1f}s (temuan: {vuln_count})")

            res_row = ScanResult.query.filter_by(
                scan_history_id=history_id, scanner_type=scanner_name
            ).first()
            if res_row:
                res_row.status = status
                res_row.raw_output = raw_out
                res_row.log_text = writer.get_text()
                res_row.parsed = parsed
                res_row.duration = duration
                res_row.vuln_count = vuln_count
                res_row.finished_at = finished_at
                db.session.commit()

            results_by_scanner[scanner_name] = res
            parsed_by_scanner[scanner_name] = parsed

        if execution_mode == "sequential":
            for s in selected_scanners:
                await execute_scanner(s)
        else:
            await asyncio.gather(*(execute_scanner(s) for s in selected_scanners))

        # ── Post-processing: correlate & build ScanFinding rows ──
        whatweb_parsed = parsed_by_scanner.get("whatweb", {})
        tech_stack = whatweb_parsed.get("tech_stack", {})
        whatweb_target = whatweb_parsed.get("target_info", {})

        wpscan_parsed = parsed_by_scanner.get("wpscan", {})
        wpscan_components = wpscan_parsed.get("components", [])
        wpscan_target = wpscan_parsed.get("target_info", {})
        wp_version = wpscan_target.get("wordpress_version") or whatweb_target.get("wordpress_version")

        nuclei_findings = (parsed_by_scanner.get("nuclei") or {}).get("findings", [])
        hardening_report = parsed_by_scanner.get("hardening") or {}

        history_db = db.session.get(ScanHistory, history_id)
        wpscan_raw = (results_by_scanner.get("wpscan") or {}).get("raw_output", "")
        if history_db and wpscan_raw:
            history_db.raw_output = wpscan_raw

        total_findings = 0
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_sev = None
        highest_rank = -1

        def _track_sev(sev):
            nonlocal highest_sev, highest_rank
            s_low = (sev or "low").lower()
            r = sev_rank.get(s_low, 1)
            if r > highest_rank:
                highest_rank = r
                highest_sev = s_low

        # 1. Nuclei findings (cross-matched with WPScan)
        for nf in nuclei_findings:
            confidence, matched_comp = assign_confidence(nf, wpscan_components)
            sev = (nf.get("severity") or "medium").lower()
            _track_sev(sev)

            evidence_parts = [
                f"Nuclei template '{nf['template_id']}' mendeteksi eksposur aktif.",
                f"URL cocok: {nf['matched_at'] or target_url}",
                f"Severity: {sev.upper()}",
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
            cve_first = nf["cve_ids"][0] if nf["cve_ids"] else None
            title = f"{nf['name']} - {nf['template_id']}"

            prompt_tpl = build_remediation_prompt({
                "component": comp_type,
                "component_name": comp_name,
                "version": comp_ver,
                "title": title,
                "severity": sev,
                "confidence": confidence,
                "cve_id": cve_first,
                "evidence_summary": evidence_summary,
            }, tech_stack=tech_stack.keys())

            db.session.add(ScanFinding(
                id=str(uuid.uuid4()),
                scan_history_id=history_id,
                component=comp_type,
                component_name=comp_name,
                version=comp_ver,
                cve_id=cve_first,
                title=title,
                confidence=confidence,
                severity=sev,
                evidence_summary=evidence_summary,
                ai_prompt_template=prompt_tpl,
                ai_status="idle",
            ))
            total_findings += 1

        # 2. WPScan components not covered by Nuclei
        for comp in wpscan_components:
            comp_name_lower = (comp["component_name"] or "").lower()
            already_covered = any(
                comp_name_lower in (nf.get("template_id") or "").lower()
                or comp_name_lower in (nf.get("name") or "").lower()
                for nf in nuclei_findings
            )
            if not already_covered:
                outdated_note = ""
                sev = "low"
                if comp.get("outdated"):
                    outdated_note = f"\nWPScan mendeteksi versi ini OUTDATED (latest: {comp.get('latest_version', '?')})."
                    sev = "medium"
                _track_sev(sev)

                evidence_summary = (
                    f"WPScan mendeteksi '{comp['component_name']}' v{comp['version'] or '?'} aktif di target.{outdated_note}\n"
                    "Nuclei tidak menemukan eksposur aktif - versi mungkin sudah dipatch atau tidak ada template yang cocok."
                )
                db.session.add(ScanFinding(
                    id=str(uuid.uuid4()),
                    scan_history_id=history_id,
                    component=comp["component_type"],
                    component_name=comp["component_name"],
                    version=comp["version"],
                    cve_id=None,
                    title=f"{comp['component_name']} - Terdeteksi WPScan",
                    confidence="Unconfirmed",
                    severity=sev,
                    evidence_summary=evidence_summary,
                    ai_prompt_template="",
                    ai_status="idle",
                ))
                total_findings += 1

        # 3. WPScan config_backups & timthumbs
        for cb in wpscan_target.get("config_backups", []):
            _track_sev("high")
            db.session.add(ScanFinding(
                id=str(uuid.uuid4()),
                scan_history_id=history_id,
                component="config",
                component_name="wp-config-backup",
                version="-",
                cve_id=None,
                title=f"Backup Konfigurasi Terekspos - {cb.get('url', '-')}",
                confidence="Confirmed",
                severity="high",
                evidence_summary=f"WPScan menemukan file backup konfigurasi di {cb.get('url', '-')}.",
                ai_status="idle",
            ))
            total_findings += 1

        for tt in wpscan_target.get("timthumbs", []):
            _track_sev("high")
            db.session.add(ScanFinding(
                id=str(uuid.uuid4()),
                scan_history_id=history_id,
                component="config",
                component_name="timthumb",
                version="-",
                cve_id=None,
                title=f"TimThumb Terekspos - {tt.get('url', '-')}",
                confidence="Confirmed",
                severity="high",
                evidence_summary=f"WPScan menemukan skrip TimThumb di {tt.get('url', '-')}.",
                ai_status="idle",
            ))
            total_findings += 1

        # 4. Hardening FAIL items
        for chk in hardening_report.get("checks", []):
            if chk.get("status") == "FAIL":
                _track_sev("high")
                db.session.add(ScanFinding(
                    id=str(uuid.uuid4()),
                    scan_history_id=history_id,
                    component="config",
                    component_name=chk.get("id") or "hardening",
                    version="-",
                    cve_id=None,
                    title=f"Hardening FAIL: {chk.get('title', 'Konfigurasi')}",
                    confidence="Confirmed",
                    severity="high",
                    evidence_summary=f"{chk.get('detail', '')}\nRekomendasi: {chk.get('recommendation', '')}".strip(),
                    ai_status="idle",
                ))
                total_findings += 1

        if history_db:
            history_db.vuln_count = total_findings
            history_db.interesting_count = len(wpscan_target.get("interesting_findings", []))
            history_db.max_severity = highest_sev or "low"
            history_db.risk_color = _compute_risk_color(total_findings, history_db.max_severity)
            history_db.duration = time.time() - start_time
            history_db.status = "scanned"
            db.session.commit()

        return "scanned", "success"

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        status, _ = loop.run_until_complete(run_pipeline())
    except Exception as exc:
        logger.exception("Scan pipeline error for history_id=%s: %s", history_id, exc)
        status = "failed"
        history_db = db.session.get(ScanHistory, history_id)
        if history_db:
            history_db.status = "failed"
            db.session.commit()
    finally:
        loop.close()

    return {
        "status": status,
        "history_id": history_id,
        "scanners": selected_scanners,
        "execution_mode": execution_mode,
    }


@shared_task(bind=True)
def ai_analyze_finding_task(self, finding_id, provider="gemini"):
    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return {"success": False, "error": "Temuan tidak ditemukan"}

    finding_dict = {
        "component": finding.component,
        "component_name": finding.component_name,
        "version": finding.version,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "cve_id": finding.cve_id,
        "evidence_summary": finding.evidence_summary,
    }
    prompt_type, prompt = build_prompt_for_finding(finding_dict)
    cache_key = compute_ai_cache_key(finding_dict, prompt_type, provider)

    # Check DB cache across identical components first
    cached = (
        ScanFinding.query.filter(
            ScanFinding.ai_cache_key == cache_key,
            ScanFinding.ai_status == "done",
            ScanFinding.ai_response.isnot(None),
        )
        .order_by(ScanFinding.ai_generated_at.desc())
        .first()
    )
    if cached and cached.ai_response:
        finding.ai_response = cached.ai_response
        finding.ai_status = "done"
        finding.ai_provider = provider
        finding.ai_generated_at = _utcnow()
        finding.ai_cache_key = cache_key
        db.session.commit()
        return {"success": True, "cached": True, "ai_response": finding.ai_response}

    finding.ai_status = "pending"
    db.session.commit()

    response = call_llm_text(prompt, provider)
    if not response or response.strip().lower().startswith("error"):
        finding.ai_status = "error"
        finding.ai_response = response or "Model Gen AI tidak mengembalikan respons."
        finding.ai_provider = provider
        db.session.commit()
        return {"success": False, "error": finding.ai_response}

    finding.ai_response = response
    finding.ai_status = "done"
    finding.ai_provider = provider
    finding.ai_generated_at = _utcnow()
    finding.ai_cache_key = cache_key
    db.session.commit()
    return {"success": True, "cached": False, "ai_response": response}


def recover_orphan_scans(max_age_seconds=3600):
    """Mark scans stuck in pending/scanning longer than max_age_seconds as failed."""
    cutoff = _utcnow() - timedelta(seconds=max_age_seconds)
    orphans = ScanHistory.query.filter(
        ScanHistory.status.in_(["pending", "scanning"]),
        ScanHistory.scanned_at < cutoff,
    ).all()
    for scan in orphans:
        scan.status = "failed"
    if orphans:
        db.session.commit()
    return len(orphans)
