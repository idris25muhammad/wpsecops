import json
import os
import shutil
from datetime import datetime, timedelta, timezone

import redis as redis_lib
from flask import Blueprint, current_app, render_template
from flask_login import login_required

from extensions import db
from models import ScanFinding, ScanHistory, Server

main_bp = Blueprint("main", __name__)


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def check_system_dependencies():
    deps = []

    # 1. WhatWeb
    whatweb_path = shutil.which("whatweb")
    deps.append({
        "name": "WhatWeb",
        "category": "FASE 1 - Identifikasi Teknologi (CMS, Server, PHP, JS Libraries)",
        "status": "ready" if whatweb_path else "missing",
        "details": f"{whatweb_path} | Mode: -a 3 --log-json=-" if whatweb_path else "Tidak terinstall. Install: apt install whatweb",
        "badge": "Siap" if whatweb_path else "Missing",
    })

    # 2. WPScan
    wpscan_path = shutil.which("wpscan")
    deps.append({
        "name": "WPScan",
        "category": "FASE 2 - WordPress Fingerprinting + Enumerasi Plugin/Tema/User (No-API)",
        "status": "ready" if wpscan_path else "missing",
        "details": f"{wpscan_path} | Mode: --enumerate vp,vt,u,tt,cb (No-API)" if wpscan_path else "Tidak terinstall di PATH",
        "badge": "No-API Mode" if wpscan_path else "Missing",
    })

    # 3. Nuclei + Templates
    nuclei_path = shutil.which("nuclei")
    env_tpl_dir = current_app.config.get("NUCLEI_TEMPLATES_DIR") or os.getenv("NUCLEI_TEMPLATES_DIR", "")
    candidate_dirs = [
        env_tpl_dir,
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.local/nuclei-templates"),
    ]
    found_template_dir = next((d for d in candidate_dirs if d and os.path.exists(d)), None)
    nuclei_ready = bool(nuclei_path and found_template_dir)
    deps.append({
        "name": "Nuclei + Templates",
        "category": "FASE 3 - WordPress Exposure Detection (-tags wordpress)",
        "status": "ready" if nuclei_ready else ("warning" if nuclei_path else "missing"),
        "details": (
            f"{nuclei_path or 'Engine missing'} | Templates: "
            f"{'OK (' + found_template_dir + ')' if found_template_dir else 'Set NUCLEI_TEMPLATES_DIR / nuclei -update-templates'}"
        ),
        "badge": "Siap & Aktif" if nuclei_ready else ("Perlu Template" if nuclei_path else "Missing"),
    })

    # 4. Celery Worker & Redis (real health check)
    broker_url = current_app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    always_eager = bool(current_app.config.get("CELERY_TASK_ALWAYS_EAGER", False))
    redis_ok = False
    workers_online = 0
    try:
        r = redis_lib.from_url(broker_url, socket_connect_timeout=0.5, socket_timeout=0.5)
        redis_ok = bool(r.ping())
    except Exception:
        redis_ok = False

    if redis_ok:
        try:
            celery_app = current_app.extensions.get("celery")
            if celery_app:
                ping = celery_app.control.inspect(timeout=0.6).ping() or {}
                workers_online = len(ping)
        except Exception:
            workers_online = 0

    if redis_ok and workers_online > 0:
        c_status, c_badge = "ready", f"{workers_online} Worker Aktif"
        c_details = f"Redis OK ({broker_url}) | Celery worker online: {workers_online}"
    elif always_eager:
        c_status, c_badge = "warning", "Eager Mode"
        c_details = "CELERY_TASK_ALWAYS_EAGER=True (berjalan sinkron di proses web)"
    elif redis_ok:
        c_status, c_badge = "warning", "Worker Offline"
        c_details = f"Redis OK, namun Celery worker tidak merespons ping"
    else:
        c_status, c_badge = "missing", "Redis Offline"
        c_details = f"Tidak dapat terhubung ke Redis ({broker_url})"

    deps.append({
        "name": "Celery Worker & Redis",
        "category": "Async Scan Pipeline",
        "status": c_status,
        "details": c_details,
        "badge": c_badge,
    })

    # 5. AI Provider
    gemini_key = bool(current_app.config.get("GEMINI_API_KEY"))
    claude_key = bool(current_app.config.get("ANTHROPIC_API_KEY"))
    ai_ready = gemini_key or claude_key
    deps.append({
        "name": "AI Recommendation Provider",
        "category": "On-Demand Intelligence (per Finding)",
        "status": "ready" if ai_ready else "warning",
        "details": f"Gemini: {'Aktif' if gemini_key else '-'} | Claude: {'Aktif' if claude_key else '-'}",
        "badge": "Siap" if ai_ready else "Tanpa API Key",
    })

    return deps


def get_celery_task_stats():
    celery_app = current_app.extensions.get("celery")
    running_scans = ScanHistory.query.filter(ScanHistory.status.in_(["scanning", "pending"])).all()

    stats = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "active_tasks_count": 0,
        "reserved_tasks_count": 0,
        "workers_online": 0,
        "running_scans_count": len(running_scans),
        "running_scans": [],
        "status": "idle",
    }

    now = _utcnow()
    for s in running_scans:
        elapsed = int((now - s.scanned_at).total_seconds()) if s.scanned_at else 0
        stats["running_scans"].append({
            "id": s.id,
            "server_id": s.server_id,
            "server_name": s.server.name if s.server else "Server",
            "target_url": s.server.url if s.server else "-",
            "status": s.status,
            "elapsed": elapsed,
        })

    try:
        if celery_app:
            insp = celery_app.control.inspect(timeout=0.6)
            if insp:
                active = insp.active() or {}
                reserved = insp.reserved() or {}
                ping = insp.ping() or {}
                stats["workers_online"] = len(ping)
                stats["active_tasks_count"] = sum(len(t) for t in active.values())
                stats["reserved_tasks_count"] = sum(len(t) for t in reserved.values())
    except Exception:
        pass

    if stats["active_tasks_count"] > 0 or stats["running_scans_count"] > 0:
        stats["status"] = "running"
    elif stats["workers_online"] > 0:
        stats["status"] = "online"
    else:
        stats["status"] = "offline"

    return stats


@main_bp.route("/dashboard")
@login_required
def dashboard():
    total_servers = Server.query.count()
    total_scans = ScanHistory.query.count()
    total_vulns = db.session.query(db.func.sum(ScanHistory.vuln_count)).scalar() or 0
    scans_done = ScanHistory.query.filter_by(status="scanned").count()
    recent_scans = ScanHistory.query.order_by(ScanHistory.scanned_at.desc()).limit(5).all()
    celery_stats = get_celery_task_stats()

    stats = {
        "total_servers": total_servers,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "scans_done": scans_done,
    }
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans, celery_stats=celery_stats)


@main_bp.route("/system-status")
@login_required
def system_status():
    dependencies = check_system_dependencies()
    return render_template("system_status.html", dependencies=dependencies)


@main_bp.route("/async-worker")
@login_required
def async_worker():
    celery_stats = get_celery_task_stats()
    return render_template("async_worker.html", celery_stats=celery_stats)


@main_bp.route("/api/celery-stats")
@login_required
def api_celery_stats():
    stats = get_celery_task_stats()
    return current_app.response_class(json.dumps(stats), mimetype="application/json")


@main_bp.route("/statistics")
@login_required
def statistics():
    total_servers = Server.query.count()
    total_scans = ScanHistory.query.count()
    total_vulns = db.session.query(db.func.sum(ScanHistory.vuln_count)).scalar() or 0
    avg_duration = db.session.query(db.func.avg(ScanHistory.duration)).scalar() or 0.0
    failed_scans = ScanHistory.query.filter_by(status="failed").count()
    scanned_scans = ScanHistory.query.filter_by(status="scanned").count()
    success_rate = (scanned_scans / total_scans * 100) if total_scans > 0 else 0.0

    # 1. Scan activity trend (last 30 days)
    today = _utcnow().date()
    thirty_days_ago = _utcnow() - timedelta(days=30)
    trend_query = (
        db.session.query(
            db.func.date(ScanHistory.scanned_at).label("scan_date"),
            db.func.count(ScanHistory.id).label("scan_count"),
        )
        .filter(ScanHistory.scanned_at >= thirty_days_ago)
        .group_by("scan_date")
        .order_by("scan_date")
        .all()
    )

    trend_data = {(today - timedelta(days=i)).isoformat(): 0 for i in range(30, -1, -1)}
    for row in trend_query:
        if row.scan_date:
            trend_data[str(row.scan_date)] = row.scan_count

    chart_trend_labels = list(trend_data.keys())
    chart_trend_values = list(trend_data.values())

    # 2. Aggregate findings directly from SQL (ScanFinding)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    component_counts = {"core": 0, "theme": 0, "plugin": 0, "wordpress": 0, "config": 0}
    provider_counts = {"gemini": 0, "anthropic": 0}
    matrix = {
        "core": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "theme": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "plugin": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    sev_comp_rows = (
        db.session.query(
            ScanFinding.severity,
            ScanFinding.component,
            db.func.count(ScanFinding.id).label("cnt"),
        )
        .group_by(ScanFinding.severity, ScanFinding.component)
        .all()
    )
    for row in sev_comp_rows:
        sev = (row.severity or "").lower()
        comp = (row.component or "").lower()
        cnt = row.cnt or 0
        if sev in severity_counts:
            severity_counts[sev] += cnt
        if comp in component_counts:
            component_counts[comp] += cnt
        if comp in matrix and sev in matrix[comp]:
            matrix[comp][sev] += cnt

    prov_rows = (
        db.session.query(ScanFinding.ai_provider, db.func.count(ScanFinding.id).label("cnt"))
        .filter(ScanFinding.ai_provider.isnot(None))
        .group_by(ScanFinding.ai_provider)
        .all()
    )
    for row in prov_rows:
        prov = (row.ai_provider or "").lower()
        if "gemini" in prov:
            provider_counts["gemini"] += row.cnt or 0
        elif "anthropic" in prov or "claude" in prov:
            provider_counts["anthropic"] += row.cnt or 0

    # 3. Server stats table
    server_stats_query = (
        db.session.query(
            Server.name.label("server_name"),
            Server.url.label("server_url"),
            db.func.count(ScanHistory.id).label("total_scans"),
            db.func.sum(db.case((ScanHistory.status == "scanned", 1), else_=0)).label("scanned_scans"),
            db.func.sum(db.case((ScanHistory.status == "failed", 1), else_=0)).label("failed_scans"),
            db.func.avg(ScanHistory.duration).label("avg_duration"),
            db.func.sum(ScanHistory.vuln_count).label("total_vulns"),
        )
        .join(ScanHistory, Server.id == ScanHistory.server_id)
        .group_by(Server.id)
        .order_by(db.func.count(ScanHistory.id).desc())
        .all()
    )

    server_stats = [
        {
            "name": row.server_name,
            "url": row.server_url,
            "total_scans": row.total_scans,
            "scanned_scans": row.scanned_scans or 0,
            "failed_scans": row.failed_scans or 0,
            "avg_duration": round(row.avg_duration or 0.0, 1),
            "total_vulns": row.total_vulns or 0,
        }
        for row in server_stats_query
    ]

    stats = {
        "total_servers": total_servers,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "avg_duration": round(avg_duration, 1),
        "success_rate": round(success_rate, 1),
        "failed_scans": failed_scans,
        "scanned_scans": scanned_scans,
    }
    ai_stats = {
        "severity": severity_counts,
        "component": {k: component_counts[k] for k in ("core", "theme", "plugin")},
        "provider": provider_counts,
    }

    return render_template(
        "statistics.html",
        stats=stats,
        trend_labels=chart_trend_labels,
        trend_values=chart_trend_values,
        ai_stats=ai_stats,
        matrix=matrix,
        server_stats=server_stats,
    )
