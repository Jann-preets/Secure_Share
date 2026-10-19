
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("APP_SECRET_KEY")
    MASTER_KEY = os.getenv("MASTER_KEY")

    MONGO_URI = os.getenv("MONGO_URI", "").strip()
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "secureshare")

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Local HTTP development only
