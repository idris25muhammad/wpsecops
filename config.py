import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "wp-secops-secret-2026")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "wpsecops.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # Session & CSRF security
    WTF_CSRF_ENABLED = os.getenv("WTF_CSRF_ENABLED", "True").lower() in ("1", "true", "yes")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = FLASK_ENV == "production"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Rate limiting
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "True").lower() in ("1", "true", "yes")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    # Admin seed
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

    CACHE_DIR = os.path.join(BASE_DIR, "ai_cache")
    VULN_ANALYZER_PROVIDER = os.getenv("VULN_ANALYZER_PROVIDER", "gemini")
    WPSCAN_API_TOKEN = os.getenv("WPSCAN_API_TOKEN")

    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
    ANTHROPIC_TIMEOUT = int(os.getenv("ANTHROPIC_TIMEOUT", "60"))

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
    GEMINI_TIMEOUT = int(os.getenv("GEMINI_TIMEOUT", "180"))

    NUCLEI_TEMPLATES_DIR = os.getenv("NUCLEI_TEMPLATES_DIR", "")

    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    CELERY_TASK_ALWAYS_EAGER = os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ("true", "1", "yes")
