from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from extensions import db, limiter
from models import Admin

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = Admin.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("main.dashboard"))

        flash("Username atau password salah.")

    return render_template("login.html")


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not check_password_hash(current_user.password, current_pw):
            flash("Password saat ini salah.")
            return redirect(url_for("auth.change_password"))
        if len(new_pw) < 8:
            flash("Password baru minimal 8 karakter.")
            return redirect(url_for("auth.change_password"))
        if new_pw != confirm_pw:
            flash("Konfirmasi password baru tidak cocok.")
            return redirect(url_for("auth.change_password"))

        current_user.password = generate_password_hash(new_pw)
        db.session.commit()
        flash("Password berhasil diperbarui.")
        return redirect(url_for("main.dashboard"))

    return render_template("change_password.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
