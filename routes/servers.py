import os
import json
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required
from extensions import db
from models import Server, ScanHistory

servers_bp = Blueprint("servers", __name__)

def extract_severity_from_vuln(v):
    cvss = v.get("cvss")
    score = None
    if isinstance(cvss, dict):
        score = cvss.get("score")
    elif isinstance(cvss, list) and len(cvss) > 0:
        scores = []
        for c in cvss:
            if isinstance(c, dict) and c.get("score") is not None:
                try:
                    scores.append(float(c.get("score")))
                except (ValueError, TypeError):
                    pass
        if scores:
            score = max(scores)
            
    if score is not None:
        try:
            score_val = float(score)
            if score_val >= 7.0: # High or Critical
                return "high"
        except (ValueError, TypeError):
            pass
    return None

@servers_bp.route("/servers", methods=["GET", "POST"])
@login_required
def servers():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        url = request.form.get("url", "").strip()

        if not name or not url:
            flash("Nama server dan URL wajib diisi.")
            return redirect(url_for("servers.servers"))

        new_server = Server(name=name, url=url)
        db.session.add(new_server)
        db.session.commit()

        flash(f'Server "{new_server.name}" berhasil ditambahkan.')
        return redirect(url_for("servers.servers"))

    page = request.args.get("page", 1, type=int)
    per_page = 9
    pagination = Server.query.order_by(Server.added_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    db_servers = pagination.items
    server_rows = []

    for s in db_servers:
        latest_scan = ScanHistory.query.filter_by(server_id=s.id) \
            .order_by(ScanHistory.scanned_at.desc()) \
            .first()

        card_color = "blue"  # Default: no scan yet
        if latest_scan:
            if latest_scan.status in ("failed", "scanning", "pending"):
                card_color = "blue"
            elif latest_scan.vuln_count == 0:
                card_color = "green"
            else:
                cache_dir = current_app.config.get("CACHE_DIR", "ai_cache")
                json_file_path = os.path.join(cache_dir, f"scan_{latest_scan.id}.json")
                has_high_crit = False

                # 1. Check AI overall severity
                if os.path.exists(json_file_path):
                    try:
                        with open(json_file_path, "r", encoding="utf-8") as f:
                            cache_data = json.load(f)
                            overall_sev = cache_data.get("overall_severity", "").lower()
                            if overall_sev in ("critical", "high"):
                                has_high_crit = True
                    except Exception:
                        pass

                # 2. Check raw wpscan output for CVSS high/crit
                if not has_high_crit and latest_scan.raw_output:
                    try:
                        parsed = json.loads(latest_scan.raw_output)
                        for v in parsed.get("version", {}).get("vulnerabilities", []) or []:
                            if extract_severity_from_vuln(v) == "high":
                                has_high_crit = True
                                break
                        if not has_high_crit:
                            for v in parsed.get("main_theme", {}).get("vulnerabilities", []) or []:
                                if extract_severity_from_vuln(v) == "high":
                                    has_high_crit = True
                                    break
                        if not has_high_crit:
                            plugins = parsed.get("plugins", {}) or {}
                            for slug, p_data in plugins.items():
                                if not isinstance(p_data, dict) or slug == "*":
                                    continue
                                for v in p_data.get("vulnerabilities", []) or []:
                                    if extract_severity_from_vuln(v) == "high":
                                        has_high_crit = True
                                        break
                                if has_high_crit:
                                    break
                    except Exception:
                        pass

                if latest_scan.vuln_count >= 5 or has_high_crit:
                    card_color = "red"
                else:
                    card_color = "yellow"

        server_rows.append({
            "id": s.id,
            "name": s.name,
            "url": s.url,
            "added_at": s.added_at,
            "last_status": latest_scan.status if latest_scan else "pending",
            "total_vulns": latest_scan.vuln_count if latest_scan else 0,
            "color": card_color,
            "last_scan_id": latest_scan.id if latest_scan else None
        })

    return render_template("servers.html", servers=server_rows, pagination=pagination)


@servers_bp.route("/servers/delete/<int:server_id>", methods=["POST"])
@login_required
def delete_server(server_id):
    server = db.session.get(Server, server_id)
    if not server:
        flash("Server tidak ditemukan.")
        return redirect(url_for("servers.servers"))

    db.session.delete(server)
    db.session.commit()
    flash(f'Server "{server.name}" berhasil dihapus.')
    return redirect(url_for("servers.servers"))


@servers_bp.route("/servers/edit/<int:server_id>", methods=["POST"])
@login_required
def edit_server(server_id):
    server = db.session.get(Server, server_id)
    if not server:
        flash("Server tidak ditemukan.")
        return redirect(url_for("servers.servers"))

    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()

    if not name or not url:
        flash("Nama server dan URL wajib diisi.")
        return redirect(url_for("servers.servers"))

    server.name = name
    server.url = url
    db.session.commit()

    flash(f'Server "{name}" berhasil diperbarui.')
    return redirect(url_for("servers.servers"))
