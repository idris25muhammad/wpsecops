import os
from flask import Blueprint, jsonify, request
from flask_login import login_required
from extensions import db
from models import ScanHistory, Server
from services.registry import PHASE_ORDER

scan_bp = Blueprint("scan", __name__)


def _build_scan_options(data):
    plugins_detection = data.get("plugins_detection") or request.args.get("plugins_detection") or "passive"
    if plugins_detection not in ("passive", "mixed", "aggressive"):
        plugins_detection = "passive"

    requested_scanners = data.get("scanners") or list(PHASE_ORDER)
    scanners = [s for s in PHASE_ORDER if s in requested_scanners] or list(PHASE_ORDER)

    execution_mode = data.get("execution_mode", "parallel")
    if execution_mode not in ("parallel", "sequential"):
        execution_mode = "parallel"

    scan_params = {
        "cookies": data.get("cookies") or None,
        "headers": data.get("headers") or [],
        "nuclei_severity": data.get("nuclei_severity") or None,
        "nuclei_tags": data.get("nuclei_tags") or None,
        "nuclei_headless": bool(data.get("nuclei_headless")),
        "execution_mode": execution_mode,
    }
    stored_params = {"plugins_detection": plugins_detection, "scanners": scanners, **scan_params}
    return plugins_detection, scanners, scan_params, stored_params


def _has_active_scan(server_id):
    return (
        ScanHistory.query.filter(
            ScanHistory.server_id == server_id,
            ScanHistory.status.in_(["pending", "scanning"]),
        ).first()
        is not None
    )


def _enqueue_scan(server, plugins_detection, scanners, scan_params, stored_params):
    from tasks import scan_task

    history = ScanHistory(
        server_id=server.id,
        status="pending",
        vuln_count=0,
        duration=0,
        params=stored_params,
    )
    db.session.add(history)
    db.session.commit()

    api_token = os.getenv("WPSCAN_API_TOKEN")
    task = scan_task.delay(
        history.id,
        server.url,
        api_token,
        plugins_detection,
        scanners=scanners,
        scan_params=scan_params,
    )
    return history, task


@scan_bp.route("/scan/<int:server_id>", methods=["POST"])
@login_required
def scan_server(server_id):
    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({"error": "Server tidak ditemukan"}), 404

    if _has_active_scan(server.id):
        return jsonify({"error": "Server ini sedang memiliki scan aktif (pending/scanning)."}), 409

    req_data = request.get_json(silent=True) or {}
    plugins_detection, scanners, scan_params, stored_params = _build_scan_options(req_data)
    history, task = _enqueue_scan(server, plugins_detection, scanners, scan_params, stored_params)

    return jsonify({
        "scan_id": history.id,
        "task_id": task.id,
        "status": "pending",
        "message": "Scan dimulai...",
        "plugins_detection": plugins_detection,
    })


@scan_bp.route("/scan/bulk", methods=["POST"])
@login_required
def bulk_scan():
    data = request.get_json(silent=True) or {}
    server_ids = data.get("server_ids", [])
    if not server_ids or not isinstance(server_ids, list):
        return jsonify({"error": "Daftar server kosong"}), 400

    plugins_detection, scanners, scan_params, stored_params = _build_scan_options(data)
    created_scans = []
    skipped = []

    for server_id in server_ids:
        server = db.session.get(Server, int(server_id))
        if not server:
            continue
        if _has_active_scan(server.id):
            skipped.append(server.name)
            continue

        history, task = _enqueue_scan(server, plugins_detection, scanners, scan_params, stored_params)
        created_scans.append({
            "server_id": server.id,
            "server_name": server.name,
            "scan_id": history.id,
            "task_id": task.id,
            "status": "pending",
        })

    if not created_scans:
        msg = "Tidak ada server valid untuk discan"
        if skipped:
            msg = f"Semua server terpilih sedang aktif discan: {', '.join(skipped)}"
        return jsonify({"error": msg}), 409 if skipped else 400

    return jsonify({
        "message": f"{len(created_scans)} scan berhasil dimulai",
        "items": created_scans,
        "skipped": skipped,
        "plugins_detection": plugins_detection,
    })


@scan_bp.route("/scan-status/<int:scan_id>", methods=["GET"])
@login_required
def get_scan_status(scan_id):
    from tasks import get_live_logs

    db.session.expire_all()
    history = db.session.get(ScanHistory, scan_id)
    if not history:
        return jsonify({"error": "Scan tidak ditemukan"}), 404

    since = request.args.get("since", 0, type=int)
    results_data = []
    for r in history.results:
        live_lines, next_offset = get_live_logs(history.id, r.scanner_type, since=since, tail=40)
        if live_lines:
            log_tail = "\n".join(live_lines)
        elif r.log_text:
            log_tail = "\n".join(r.log_text.splitlines()[-40:])
        else:
            log_tail = ""

        results_data.append({
            "scanner_type": r.scanner_type,
            "status": r.status,
            "vuln_count": r.vuln_count or 0,
            "duration": r.duration or 0,
            "log_tail": log_tail,
            "log_offset": next_offset,
        })

    return jsonify({
        "success": True,
        "scan_id": history.id,
        "status": history.status,
        "vuln_count": history.vuln_count or 0,
        "duration": history.duration or 0,
        "results": results_data,
    })
