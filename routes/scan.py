import os
from flask import Blueprint, request, jsonify
from flask_login import login_required
from extensions import db
from models import Server, ScanHistory

scan_bp = Blueprint("scan", __name__)

@scan_bp.route("/scan/<int:server_id>", methods=["POST"])
@login_required
def scan_server(server_id):
    from tasks import scan_task

    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({"error": "Server tidak ditemukan"}), 404

    req_data = request.get_json(silent=True) or {}
    plugins_detection = req_data.get("plugins_detection") or request.args.get("plugins_detection") or "passive"
    if plugins_detection not in ("passive", "mixed", "aggressive"):
        plugins_detection = "passive"

    scanners = req_data.get("scanners") or ["whatweb", "wpscan", "nuclei", "hardening"]

    scan_params = {
        "cookies": req_data.get("cookies") or None,
        "headers": req_data.get("headers") or [],
        "nuclei_severity": req_data.get("nuclei_severity") or None,
        "nuclei_tags": req_data.get("nuclei_tags") or None,
        "nuclei_headless": bool(req_data.get("nuclei_headless")),
    }

    history = ScanHistory(
        server_id=server.id,
        status="pending",
        vuln_count=0,
        duration=0,
        params={
            "plugins_detection": plugins_detection,
            "scanners": scanners,
            "cookies": scan_params.get("cookies"),
            "headers": scan_params.get("headers") or [],
            "nuclei_severity": scan_params.get("nuclei_severity"),
            "nuclei_tags": scan_params.get("nuclei_tags"),
            "nuclei_headless": bool(scan_params.get("nuclei_headless")),
        }
    )
    db.session.add(history)
    db.session.commit()

    api_token = os.getenv("WPSCAN_API_TOKEN")
    task = scan_task.delay(history.id, server.url, api_token, plugins_detection, scanners=scanners, scan_params=scan_params)

    return jsonify({
        "scan_id": history.id,
        "task_id": task.id,
        "status": "pending",
        "message": "Scan dimulai...",
        "plugins_detection": plugins_detection
    })


@scan_bp.route("/scan/bulk", methods=["POST"])
@login_required
def bulk_scan():
    from tasks import scan_task

    data = request.get_json(silent=True) or {}
    server_ids = data.get("server_ids", [])
    plugins_detection = data.get("plugins_detection") or "passive"
    if plugins_detection not in ("passive", "mixed", "aggressive"):
        plugins_detection = "passive"

    scanners = data.get("scanners") or ["whatweb", "wpscan", "nuclei", "hardening"]

    scan_params = {
        "cookies": data.get("cookies") or None,
        "headers": data.get("headers") or [],
        "nuclei_severity": data.get("nuclei_severity") or None,
        "nuclei_tags": data.get("nuclei_tags") or None,
        "nuclei_headless": bool(data.get("nuclei_headless")),
    }

    if not server_ids or not isinstance(server_ids, list):
        return jsonify({"error": "Daftar server kosong"}), 400

    created_scans = []

    for server_id in server_ids:
        server = db.session.get(Server, int(server_id))
        if not server:
            continue

        history = ScanHistory(
            server_id=server.id,
            status="pending",
            vuln_count=0,
            duration=0,
            params={
                "plugins_detection": plugins_detection,
                "scanners": scanners,
                "cookies": scan_params.get("cookies"),
                "headers": scan_params.get("headers") or [],
                "nuclei_severity": scan_params.get("nuclei_severity"),
                "nuclei_tags": scan_params.get("nuclei_tags"),
                "nuclei_headless": bool(scan_params.get("nuclei_headless")),
            }
        )
        db.session.add(history)
        db.session.commit()

        api_token = os.getenv("WPSCAN_API_TOKEN")
        task = scan_task.delay(history.id, server.url, api_token, plugins_detection, scanners=scanners, scan_params=scan_params)

        created_scans.append({
            "server_id": server.id,
            "server_name": server.name,
            "scan_id": history.id,
            "task_id": task.id,
            "status": "pending"
        })

    if not created_scans:
        return jsonify({"error": "Tidak ada server valid untuk discan"}), 400

    return jsonify({
        "message": f"{len(created_scans)} scan berhasil dimulai",
        "items": created_scans,
        "plugins_detection": plugins_detection
    })


@scan_bp.route("/scan-status/<int:scan_id>", methods=["GET"])
@login_required
def get_scan_status(scan_id):
    db.session.expire_all()
    history = db.session.get(ScanHistory, scan_id)
    if not history:
        return jsonify({"error": "Scan tidak ditemukan"}), 404

    results_data = []
    for r in history.results:
        results_data.append({
            "scanner_type": r.scanner_type,
            "status": r.status,
            "vuln_count": r.vuln_count or 0,
            "duration": r.duration or 0,
            "raw_output": r.raw_output or ""
        })

    return jsonify({
        "success": True,
        "scan_id": history.id,
        "status": history.status,
        "vuln_count": history.vuln_count or 0,
        "duration": history.duration or 0,
        "results": results_data
    })
