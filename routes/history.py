import os
from datetime import timedelta, timezone
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required
from extensions import db
from models import ScanFinding, ScanHistory, Server
from services.parsers import parse_hardening, parse_nuclei, parse_whatweb, parse_wpscan
from services.registry import PHASE_ORDER, SCANNERS

history_bp = Blueprint("history", __name__)

LOG_PREFIXES = ("[WHATWEB]", "[WPSCAN]", "[NUCLEI]", "[HARDENING]", "[SYSTEM]")


def _severity_from_confidence(confidence):
    if confidence in ("Cross-verified", "Confirmed"):
        return "high"
    if confidence == "Likely":
        return "medium"
    return "low"


def get_scan_findings_and_info(scan):
    """Build target_info and interesting_findings from ScanResult.parsed (or raw_output fallback)."""
    target_info = {
        "wordpress_version": "-",
        "main_theme": "-",
        "theme_details": {},
        "themes_detected": [],
        "plugins_detected": [],
        "plugin_details": [],
        "users_detected": [],
        "user_details": [],
        "timthumbs": [],
        "config_backups": [],
        "interesting_urls": [],
        "target_ip": None,
        "effective_url": None,
        "scan_stats": {},
        "tech_stack": [],
        "server": None,
        "php_version": None,
    }
    interesting_findings = []
    findings = []

    results_map = {r.scanner_type: r for r in (scan.results or [])}

    # 1. WhatWeb
    ww_res = results_map.get("whatweb")
    if ww_res:
        ww_parsed = ww_res.parsed if isinstance(ww_res.parsed, dict) else parse_whatweb(ww_res.raw_output)
        ww_ti = ww_parsed.get("target_info", {})
        target_info["tech_stack"] = ww_ti.get("technologies", [])
        if ww_ti.get("wordpress_version"):
            target_info["wordpress_version"] = ww_ti["wordpress_version"]
        if ww_ti.get("server"):
            target_info["server"] = ww_ti["server"]
        if ww_ti.get("php_version"):
            target_info["php_version"] = ww_ti["php_version"]

    # 2. WPScan
    wp_res = results_map.get("wpscan")
    wp_raw = wp_res.raw_output if (wp_res and wp_res.raw_output) else None
    if not wp_raw and scan.raw_output and scan.raw_output.strip().startswith("{"):
        wp_raw = scan.raw_output
    if wp_res and isinstance(wp_res.parsed, dict) and wp_res.parsed.get("target_info"):
        wp_parsed = wp_res.parsed
    elif wp_raw:
        wp_parsed = parse_wpscan(wp_raw)
    else:
        wp_parsed = {}

    wp_ti = wp_parsed.get("target_info", {})
    if wp_ti:
        if wp_ti.get("wordpress_version"):
            target_info["wordpress_version"] = wp_ti["wordpress_version"]
        for key in (
            "main_theme", "theme_details", "themes_detected", "plugins_detected",
            "plugin_details", "users_detected", "user_details", "timthumbs",
            "config_backups", "interesting_urls", "target_ip", "effective_url", "scan_stats",
        ):
            if wp_ti.get(key):
                target_info[key] = wp_ti[key]
        interesting_findings = wp_ti.get("interesting_findings", [])

    # 3. Nuclei (for legacy fallback)
    nuc_res = results_map.get("nuclei")
    if nuc_res:
        nuc_parsed = nuc_res.parsed if isinstance(nuc_res.parsed, dict) else parse_nuclei(nuc_res.raw_output)
        for idx, nf in enumerate(nuc_parsed.get("findings", []), 1):
            sev = (nf.get("severity") or "medium").lower()
            findings.append({
                "index": idx,
                "component": "wordpress",
                "component_name": nf.get("template_id") or "Nuclei",
                "title": nf.get("name") or "Nuclei Finding",
                "fixed_in": None,
                "references": {"url": [nf.get("matched_at")]} if nf.get("matched_at") else {},
                "cve_ids": nf.get("cve_ids") or [],
                "severity": sev,
                "severity_reason": f"Nuclei template '{nf.get('template_id')}' mendeteksi eksposur aktif ({sev.upper()}).",
                "recommendations": [nf.get("remediation")] if nf.get("remediation") else None,
                "matched_at": nf.get("matched_at", ""),
                "is_ai": False,
                "scanner": "nuclei",
            })

    return findings, None, target_info, interesting_findings


def get_hardening_report(scan):
    for r in (scan.results or []):
        if r.scanner_type == "hardening":
            if isinstance(r.parsed, dict) and r.parsed:
                return r.parsed
            if r.raw_output:
                return parse_hardening(r.raw_output)
    return None


@history_bp.route("/history")
@login_required
def history():
    server_id = request.args.get("server_id", type=int)
    page = request.args.get("page", 1, type=int)
    per_page = 15

    query = ScanHistory.query.order_by(ScanHistory.scanned_at.desc())
    if server_id:
        query = query.filter_by(server_id=server_id)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    all_servers = Server.query.order_by(Server.name.asc()).all()

    return render_template(
        "history.html",
        histories=pagination.items,
        pagination=pagination,
        servers=all_servers,
        selected=server_id,
    )


@history_bp.route("/history/<int:scan_id>")
@login_required
def history_detail(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.")
        return redirect(url_for("history.history"))

    findings_raw, api_error, target_info, interesting_findings = get_scan_findings_and_info(scan)

    findings = []
    if scan.findings_list:
        for idx, f in enumerate(scan.findings_list, 1):
            sev = (f.severity or _severity_from_confidence(f.confidence)).lower()
            findings.append({
                "id": f.id,
                "index": idx,
                "component": f.component,
                "component_name": f.component_name,
                "version": f.version,
                "cve_id": f.cve_id,
                "cve_ids": [f.cve_id] if f.cve_id else [],
                "title": f.title,
                "confidence": f.confidence,
                "evidence_summary": f.evidence_summary,
                "ai_prompt_template": f.ai_prompt_template,
                "ai_response": f.ai_response,
                "ai_status": f.ai_status or ("done" if f.ai_response else "idle"),
                "ai_provider": f.ai_provider,
                "manual_note": f.manual_note,
                "is_ai": bool(f.ai_response),
                "severity": sev,
                "scanner": "pipeline",
            })
    else:
        for f in findings_raw:
            f["id"] = None
            f["confidence"] = "Unconfirmed"
            f["evidence_summary"] = "Legacy scan. Detail verifikasi tidak tersedia."
            f["ai_prompt_template"] = ""
            f["ai_response"] = f.get("recommendations", [None])[0] if f.get("recommendations") else None
            f["ai_status"] = "done" if f["ai_response"] else "idle"
            f["manual_note"] = None
            f["is_ai"] = bool(f["ai_response"])
            findings.append(f)

    findings_count = len(findings)
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    highest_level = -1
    highest_name = None
    for f in findings:
        sev = f.get("severity")
        if sev in levels and levels[sev] > highest_level:
            highest_level = levels[sev]
            highest_name = sev

    overall_severity = highest_name if highest_name else "low"
    if findings_count == 0:
        overall_summary = "Tidak ada kerentanan terdeteksi."
        overall_recommendations = []
    else:
        overall_summary = f"Terdeteksi {findings_count} temuan keamanan."
        overall_recommendations = [
            "Segera lakukan patching/update pada komponen dengan tingkat risiko tinggi/terkonfirmasi.",
            "Gunakan tombol 'Minta Rekomendasi AI' pada masing-masing temuan di bawah untuk langkah mitigasi spesifik.",
        ]

    merged_ai_analysis = {
        "is_fallback": False,
        "findings": findings,
        "overall_severity": overall_severity,
        "overall_summary": overall_summary,
        "overall_recommendations": overall_recommendations,
    }

    return render_template(
        "history_ai.html",
        h=scan,
        ai_analysis=merged_ai_analysis,
        findings_count=findings_count,
        target_info=target_info,
        api_error=api_error,
        interesting_findings=interesting_findings,
        hardening=get_hardening_report(scan),
    )


def _extract_log_lines(res):
    if res.log_text:
        return [line.strip() for line in res.log_text.splitlines() if line.strip()]
    out = []
    for line in (res.raw_output or "").splitlines():
        s = line.strip()
        if s.startswith(LOG_PREFIXES) or s.startswith("\u2501\u2501\u2501"):
            out.append(s)
    return out


def _utc_to_local_str(dt):
    if not dt:
        return "\u2014"
    try:
        return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%H:%M:%S")
    except Exception:
        return dt.strftime("%H:%M:%S")


def build_pipeline_timeline(scan):
    """Susun timeline 4 fase dari ScanResult (memakai started_at/finished_at jika ada)."""
    results = {r.scanner_type: r for r in (scan.results or [])}
    cursor = scan.scanned_at
    timeline = []
    for st in PHASE_ORDER:
        res = results.get(st)
        spec = SCANNERS[st]
        if res:
            duration = res.duration or 0.0
            start = res.started_at or cursor
            end = res.finished_at or (start + timedelta(seconds=duration) if start else start)
            cursor = end
            timeline.append({
                "scanner_type": st,
                "label": spec.label,
                "desc": spec.desc,
                "color": spec.color,
                "status": res.status,
                "duration": duration,
                "start_str": _utc_to_local_str(start),
                "end_str": _utc_to_local_str(end),
                "vuln_count": res.vuln_count or 0,
                "logs": _extract_log_lines(res),
                "raw_output": res.raw_output or "",
            })
        else:
            timeline.append({
                "scanner_type": st,
                "label": spec.label,
                "desc": spec.desc,
                "color": spec.color,
                "status": "missing",
                "duration": 0,
                "start_str": _utc_to_local_str(cursor),
                "end_str": _utc_to_local_str(cursor),
                "vuln_count": 0,
                "logs": [],
                "raw_output": "",
            })
    return timeline


@history_bp.route("/history/<int:scan_id>/workflow")
@login_required
def workflow_timeline(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.")
        return redirect(url_for("history.history"))
    return render_template("workflow.html", h=scan, timeline=build_pipeline_timeline(scan))


@history_bp.route("/history/<int:scan_id>/pipeline")
@login_required
def pipeline_timeline(scan_id):
    return redirect(url_for("history.workflow_timeline", scan_id=scan_id))


@history_bp.route("/history/finding/<string:finding_id>/analyze", methods=["POST"])
@login_required
def analyze_finding(finding_id):
    from tasks import ai_analyze_finding_task

    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "error": "Temuan tidak ditemukan"}), 404

    req_data = request.get_json(silent=True) or {}
    provider = req_data.get("provider", "gemini").strip().lower()
    if provider not in ("gemini", "anthropic", "claude"):
        return jsonify({
            "success": False,
            "error": f"Provider Gen AI '{provider}' tidak didukung. Pilih 'gemini' atau 'claude'.",
        }), 400

    finding.ai_status = "pending"
    finding.ai_provider = provider
    db.session.commit()

    task = ai_analyze_finding_task.delay(finding.id, provider)
    db.session.refresh(finding)

    # In eager mode (or cache hit), response is already ready immediately
    if finding.ai_status == "done":
        return jsonify({
            "success": True,
            "status": "done",
            "ai_response": finding.ai_response,
            "provider": finding.ai_provider,
        }), 200
    if finding.ai_status == "error":
        return jsonify({
            "success": False,
            "status": "error",
            "error": finding.ai_response or "Gagal memanggil Gen AI",
        }), 500

    return jsonify({
        "success": True,
        "status": "pending",
        "job_id": task.id,
    }), 202


@history_bp.route("/history/finding/<string:finding_id>/status", methods=["GET"])
@login_required
def finding_ai_status(finding_id):
    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "error": "Temuan tidak ditemukan"}), 404
    return jsonify({
        "success": finding.ai_status != "error",
        "status": finding.ai_status or "idle",
        "ai_response": finding.ai_response,
        "provider": finding.ai_provider,
        "error": finding.ai_response if finding.ai_status == "error" else None,
    })


@history_bp.route("/history/finding/<string:finding_id>/note", methods=["POST"])
@login_required
def save_finding_note(finding_id):
    finding = db.session.get(ScanFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "error": "Temuan tidak ditemukan"}), 404

    req_data = request.get_json(silent=True) or {}
    finding.manual_note = req_data.get("note", "")
    db.session.commit()
    return jsonify({"success": True})


@history_bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_history(scan_id):
    scan = db.session.get(ScanHistory, scan_id)
    if not scan:
        flash("History scan tidak ditemukan.", "error")
        return redirect(url_for("history.history"))

    cache_dir = current_app.config.get("CACHE_DIR", "ai_cache")
    json_file_path = os.path.join(cache_dir, f"scan_{scan_id}.json")
    if os.path.exists(json_file_path):
        try:
            os.remove(json_file_path)
        except Exception:
            pass

    db.session.delete(scan)
    db.session.commit()

    flash("Riwayat scan berhasil dihapus.")
    return redirect(url_for("history.history"))
