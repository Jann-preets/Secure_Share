
import re
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_user, logout_user, login_required
from pymongo.errors import DuplicateKeyError

from security.user import User

auth = Blueprint("auth", __name__)


@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or len(username) < 3 or len(username) > 30:
            flash("Username must be between 3 and 30 characters.", "error")
            return render_template("register.html")

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
            flash("Username can contain letters, numbers, dots, underscores and hyphens only.", "error")
            return render_template("register.html")

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        if len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        db = current_app.extensions.get("mongo_db")
        if db is None:
            flash("Database is unavailable. Please try again later.", "error")
            return render_template("register.html"), 503

        if db.users.find_one({
            "$or": [{"email": email}, {"username": username}]
        }):
            flash("That email or username is already registered.", "error")
            return render_template("register.html")

        from bson import ObjectId

        document = {
            "_id": ObjectId(),
            "username": username,
            "email": email,
            "password_hash": User.hash_password(password),
        }

        try:
            db.users.insert_one(document)
        except DuplicateKeyError:
            flash("That email or username is already registered.", "error")
            return render_template("register.html")

        flash("Account created successfully. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = current_app.extensions.get("mongo_db")
        if db is None:
            flash("Database is unavailable. Please try again later.", "error")
            return render_template("login.html"), 503

        document = db.users.find_one({"email": email})

        if document:
            user = User.from_document(document)
            if user.verify_password(password):
                login_user(user)
                flash("Welcome back!", "success")
                return redirect(url_for("dashboard.index"))
        flash("Invalid email or password.", "error")

    return render_template("login.html")


@auth.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
