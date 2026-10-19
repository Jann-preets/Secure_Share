from flask import Flask, render_template, redirect, url_for
from flask_login import current_user
from pymongo import MongoClient
from pymongo.errors import PyMongoError
import certifi
from routes.auth import auth
from config import Config
from extensions import login_manager, csrf, limiter
from routes.dashboard import dashboard
from routes.files import files_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    if not app.config["SECRET_KEY"]:
        raise RuntimeError("APP_SECRET_KEY is missing from .env")

    if not app.config["MASTER_KEY"]:
        raise RuntimeError("MASTER_KEY is missing from .env")

    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    app.register_blueprint(auth)
    app.register_blueprint(dashboard)
    app.register_blueprint(files_bp)

    app.extensions["mongo_client"] = None
    app.extensions["mongo_db"] = None
    app.extensions["mongo_status"] = "Not configured"

    mongo_uri = app.config["MONGO_URI"]

    if mongo_uri:
        client = MongoClient(
        mongo_uri,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=10000,
    )

        try:
            client.admin.command("ping")
            app.extensions["mongo_client"] = client
            app.extensions["mongo_db"] = client[
                app.config["MONGO_DB_NAME"]
            ]
            app.extensions["mongo_status"] = "Connected"
            app.extensions["mongo_db"].users.create_index(
                "email",
                unique=True,
            )
            app.extensions["mongo_db"].users.create_index(
                "username",
                unique=True,
            )
        except PyMongoError as error:
            print("MongoDB connection error:", type(error).__name__)
            print("Details:", str(error).splitlines()[0])

            client.close()
            app.extensions["mongo_status"] = "Connection failed"

    
    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))

        return redirect(url_for("auth.login"))


    @app.route("/health")
    def health():
        return {
            "app": "running",
            "mongodb": app.extensions["mongo_status"],
        }

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
    )
