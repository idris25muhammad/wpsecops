from urllib.parse import urlparse
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import and_
from extensions import db
from models import ScanHistory, Server

servers_bp = Blueprint("servers", __name__)


def validate_target_url(raw_url):
    """Validate target URL: must be http/https with valid hostname and no leading '-'."""
    url = (raw_url or "").strip()
    if not url or url.startswith("-"):
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    if any(ch.isspace() for ch in url):
        return None
    return url


@servers_bp.route("/servers", methods=["GET", "POST"])
@login_required
def servers():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        url = validate_target_url(request.form.get("url", ""))

        if not name or not url:
            flash("Nama server dan URL valid (http:// atau https://) wajib diisi.")
            return redirect(url_for("servers.servers"))

        new_server = Server(name=name, url=url)
        db.session.add(new_server)
        db.session.commit()

        flash(f'Server "{new_server.name}" berhasil ditambahkan.')
        return redirect(url_for("servers.servers"))

    page = request.args.get("page", 1, type=int)
    per_page = 9
    pagination = Server.query.order_by(Server.added_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    db_servers = pagination.items
    server_ids = [s.id for s in db_servers]

    latest_by_server = {}
    if server_ids:
        latest_sub = (
            db.session.query(
                ScanHistory.server_id,
                db.func.max(ScanHistory.id).label("max_id"),
            )
            .filter(ScanHistory.server_id.in_(server_ids))
            .group_by(ScanHistory.server_id)
            .subquery()
        )
        latest_rows = (
            db.session.query(ScanHistory)
            .join(latest_sub, and_(
                ScanHistory.server_id == latest_sub.c.server_id,
                ScanHistory.id == latest_sub.c.max_id,
            ))
            .all()
        )
        latest_by_server = {row.server_id: row for row in latest_rows}

    server_rows = []
    for s in db_servers:
        latest_scan = latest_by_server.get(s.id)
        card_color = "blue"
        if latest_scan:
            if latest_scan.status in ("failed", "scanning", "pending"):
                card_color = "blue"
            elif latest_scan.risk_color in ("green", "yellow", "red"):
                card_color = latest_scan.risk_color
            elif latest_scan.vuln_count == 0:
                card_color = "green"
            elif latest_scan.vuln_count >= 5 or (latest_scan.max_severity or "").lower() in ("critical", "high"):
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
            "last_scan_id": latest_scan.id if latest_scan else None,
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
    url = validate_target_url(request.form.get("url", ""))

    if not name or not url:
        flash("Nama server dan URL valid (http:// atau https://) wajib diisi.")
        return redirect(url_for("servers.servers"))

    server.name = name
    server.url = url
    db.session.commit()

    flash(f'Server "{name}" berhasil diperbarui.')
    return redirect(url_for("servers.servers"))
