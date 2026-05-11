from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, session, url_for

from apk_web.auth import login_required, password_hash_configured, verify_login

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("pages.dashboard"))
    err = None
    if request.method == "POST":
        pw = request.form.get("password") or ""
        if verify_login(pw):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("pages.dashboard"))
        err = "Invalid password."
    return render_template(
        "login.html",
        error=err,
        auth_configured=password_hash_configured(),
    )


@pages_bp.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("pages.login"))


@pages_bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")
