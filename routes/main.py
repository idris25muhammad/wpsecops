import os
import json
import glob
from datetime import datetime, timedelta
from flask import Blueprint, render_template, current_app
from flask_login import login_required
from extensions import db
from models import Server, ScanHistory

main_bp = Blueprint("main", __name__)

import shutil

def check_system_dependencies():
    deps = []

    # 1. WhatWeb (FASE 1 - Technology Identification)
    whatweb_path = shutil.which("whatweb")
    deps.append({
        "name": "WhatWeb",
        "category": "FASE 1 - Identifikasi Teknologi (CMS, Server, PHP, JS Libraries)",
        "status": "ready" if whatweb_path else "missing",
        "details": f"{whatweb_path} | Mode: -a 3 --log-json=-" if whatweb_path else "Tidak terinstall. Install: apt install whatweb",
        "badge": "Siap" if whatweb_path else "Missing"
    })

    # 2. WPScan (FASE 2 - No-API Fingerprinting + Enumeration)
    wpscan_path = shutil.which("wpscan")
    deps.append({
        "name": "WPScan",
        "category": "FASE 2 - WordPress Fingerprinting + Enumerasi Plugin/Tema/User (No-API)",
        "status": "ready" if wpscan_path else "missing",
        "details": f"{wpscan_path} | Mode: --enumerate ap,at,u,tt (tanpa --api-token)" if wpscan_path else "Tidak terinstall di PATH",
        "badge": "No-API Mode" if wpscan_path else "Missing"
    })

    # 3. Nuclei + Templates (FASE 3 - Exposure Detection)
    nuclei_path = shutil.which("nuclei")
    templates_dir = "/home/idris/nuclei-templates"
    templates_exist = os.path.exists(templates_dir)
    nuclei_ready = bool(nuclei_path and templates_exist)
    deps.append({
        "name": "Nuclei + Templates",
        "category": "FASE 3 - WordPress Exposure Detection (-tags wordpress)",
        "status": "ready" if nuclei_ready else ("warning" if nuclei_path else "missing"),
        "details": f"{nuclei_path or 'Engine missing'} | Templates: {'OK (/home/idris/nuclei-templates)' if templates_exist else 'Missing'}",
        "badge": "Siap & Aktif" if nuclei_ready else ("Perlu Template" if nuclei_path else "Missing")
    })

    # 4. Celery Worker & Redis
    deps.append({
        "name": "Celery Worker & Redis",
        "category": "Async Scan Pipeline",
        "status": "ready",
        "details": "Antrean tugas asynchronous aktif",
        "badge": "Aktif"
    })

    # 5. AI Provider
    gemini_key = bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
    claude_key = bool(os.getenv("ANTHROPIC_API_KEY"))
    ai_ready = gemini_key or claude_key
    ai_details = f"Gemini: {'Aktif' if gemini_key else '-'} | Claude: {'Aktif' if claude_key else '-'}"
    deps.append({
        "name": "AI Recommendation Provider",
        "category": "On-Demand Intelligence (per Finding)",
        "status": "ready" if ai_ready else "warning",
        "details": ai_details,
        "badge": "Siap" if ai_ready else "Tanpa API Key"
    })

    return deps



def get_celery_task_stats():
    from tasks import celery_app
    running_scans = ScanHistory.query.filter(ScanHistory.status.in_(["scanning", "pending"])).all()
    
    stats = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "active_tasks_count": 0,
        "reserved_tasks_count": 0,
        "workers_online": 0,
        "running_scans_count": len(running_scans),
        "running_scans": [],
        "status": "idle"
    }
    
    for s in running_scans:
        elapsed = int((datetime.utcnow() - s.scanned_at).total_seconds()) if s.scanned_at else 0
        stats["running_scans"].append({
            "id": s.id,
            "server_id": s.server_id,
            "server_name": s.server.name if s.server else "Server",
            "target_url": s.server.url if s.server else "-",
            "status": s.status,
            "elapsed": elapsed
        })

    try:
        i = celery_app.control.inspect(timeout=0.8)
        if i:
            active = i.active() or {}
            reserved = i.reserved() or {}
            ping = i.ping() or {}
            
            stats["workers_online"] = len(ping)
            stats["active_tasks_count"] = sum(len(tasks) for tasks in active.values())
            stats["reserved_tasks_count"] = sum(len(tasks) for tasks in reserved.values())
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
        "scans_done": scans_done
    }

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans,
        celery_stats=celery_stats
    )


@main_bp.route("/system-status")
@login_required
def system_status():
    dependencies = check_system_dependencies()
    return render_template(
        "system_status.html",
        dependencies=dependencies
    )


@main_bp.route("/async-worker")
@login_required
def async_worker():
    celery_stats = get_celery_task_stats()
    return render_template(
        "async_worker.html",
        celery_stats=celery_stats
    )


@main_bp.route("/api/celery-stats")
@login_required
def api_celery_stats():
    stats = get_celery_task_stats()
    return current_app.response_class(
        json.dumps(stats),
        mimetype='application/json'
    )




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
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    trend_query = db.session.query(
        db.func.date(ScanHistory.scanned_at).label("scan_date"),
        db.func.count(ScanHistory.id).label("scan_count")
    ).filter(ScanHistory.scanned_at >= thirty_days_ago)\
     .group_by("scan_date")\
     .order_by("scan_date").all()

    # Pre-populate list of past 30 days so we have zeros for days without scans
    trend_data = {}
    for i in range(30, -1, -1):
        date_str = (datetime.utcnow().date() - timedelta(days=i)).isoformat()
        trend_data[date_str] = 0

    for row in trend_query:
        if row.scan_date:
            trend_data[row.scan_date] = row.scan_count

    # Convert to sorted list of dicts for frontend chart
    chart_trend_labels = list(trend_data.keys())
    chart_trend_values = list(trend_data.values())

    # 2. Extract AI vulnerability details from cache files
    cache_dir = current_app.config.get("CACHE_DIR", "ai_cache")
    cache_files = glob.glob(os.path.join(cache_dir, "scan_*.json"))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    component_counts = {"core": 0, "theme": 0, "plugin": 0}
    provider_counts = {"gemini": 0, "anthropic": 0}

    # Matrix: component -> severity
    matrix = {
        "core": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "theme": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "plugin": {"critical": 0, "high": 0, "medium": 0, "low": 0}
    }

    for file_path in cache_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", {})
                
                # findings could be a dict (index -> finding) or list
                findings_items = []
                if isinstance(findings, dict):
                    findings_items = list(findings.values())
                elif isinstance(findings, list):
                    findings_items = findings

                for item in findings_items:
                    sev = item.get("severity", "").lower()
                    comp = item.get("component", "").lower()
                    prov = item.get("provider", "").lower()

                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    if comp in component_counts:
                        component_counts[comp] += 1
                    
                    if comp in matrix and sev in matrix[comp]:
                        matrix[comp][sev] += 1

                    if "gemini" in prov:
                        provider_counts["gemini"] += 1
                    elif "anthropic" in prov or "claude" in prov:
                        provider_counts["anthropic"] += 1
        except Exception:
            pass

    # 3. Server stats table query
    server_stats_query = db.session.query(
        Server.name.label("server_name"),
        Server.url.label("server_url"),
        db.func.count(ScanHistory.id).label("total_scans"),
        db.func.sum(db.case((ScanHistory.status == 'scanned', 1), else_=0)).label("scanned_scans"),
        db.func.sum(db.case((ScanHistory.status == 'failed', 1), else_=0)).label("failed_scans"),
        db.func.avg(ScanHistory.duration).label("avg_duration"),
        db.func.sum(ScanHistory.vuln_count).label("total_vulns")
    ).join(ScanHistory, Server.id == ScanHistory.server_id)\
     .group_by(Server.id)\
     .order_by(db.func.count(ScanHistory.id).desc()).all()

    server_stats = []
    for row in server_stats_query:
        server_stats.append({
            "name": row.server_name,
            "url": row.server_url,
            "total_scans": row.total_scans,
            "scanned_scans": row.scanned_scans or 0,
            "failed_scans": row.failed_scans or 0,
            "avg_duration": round(row.avg_duration or 0.0, 1),
            "total_vulns": row.total_vulns or 0
        })

    stats = {
        "total_servers": total_servers,
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "avg_duration": round(avg_duration, 1),
        "success_rate": round(success_rate, 1),
        "failed_scans": failed_scans,
        "scanned_scans": scanned_scans
    }

    ai_stats = {
        "severity": severity_counts,
        "component": component_counts,
        "provider": provider_counts
    }

    return render_template(
        "statistics.html",
        stats=stats,
        trend_labels=chart_trend_labels,
        trend_values=chart_trend_values,
        ai_stats=ai_stats,
        matrix=matrix,
        server_stats=server_stats
    )


