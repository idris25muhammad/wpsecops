import logging
import os
import secrets
from flask import Flask, jsonify
from werkzeug.security import generate_password_hash
from config import Config
from extensions import celery_init_app, csrf, db, limiter, login_manager, migrate
from models import Admin
from routes import register_routes

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wpsecops")


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    if (
        app.config.get("FLASK_ENV") == "production"
        and app.config.get("SECRET_KEY") == "wp-secops-secret-2026"
    ):
        raise RuntimeError(
            "FLASK_SECRET_KEY masih menggunakan nilai default di mode production! "
            "Set FLASK_SECRET_KEY yang aman di .env."
        )

    cache_dir = app.config.get("CACHE_DIR", "ai_cache")
    if cache_dir and not os.path.exists(cache_dir):
        os.makedirs(cache_dir, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)
    celery_init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(Admin, int(user_id))

    register_routes(app)

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"}), 200

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        logger.info("Database initialized.")

    if app.config.get("AUTO_INIT_DB", True):
        with app.app_context():
            init_db()

    return app


def _migrate_schema():
    """Migrasi ringan: tambahkan kolom baru yang belum ada di DB lama."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    dialect = db.engine.dialect.name

    migrations = {
        "scan_history": {
            "params": "JSON",
            "interesting_count": "INTEGER DEFAULT 0",
            "max_severity": "VARCHAR(20)",
            "risk_color": "VARCHAR(20)",
        },
        "scan_result": {
            "log_text": "TEXT",
            "parsed": "JSON",
            "started_at": "DATETIME",
            "finished_at": "DATETIME",
        },
        "scan_finding": {
            "ai_status": "VARCHAR(20) DEFAULT 'idle'",
            "ai_provider": "VARCHAR(30)",
            "ai_generated_at": "DATETIME",
            "ai_cache_key": "VARCHAR(64)",
        },
    }

    for table, cols_to_add in migrations.items():
        if table not in tables:
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        for col_name, col_type in cols_to_add.items():
            if col_name not in existing:
                sql_type = col_type
                if dialect == "mysql" and col_type.startswith("JSON"):
                    sql_type = "JSON"
                with db.engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {sql_type}"))


def init_db():
    db.create_all()
    _migrate_schema()

    if not Admin.query.first():
        username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
        password = os.getenv("ADMIN_PASSWORD", "").strip()
        if not password:
            password = secrets.token_urlsafe(12)
            logger.warning(
                "ADMIN_PASSWORD tidak diset. Akun admin awal dibuat: username=%s password=%s (segera ganti setelah login!)",
                username,
                password,
            )
        admin = Admin(username=username, password=generate_password_hash(password))
        db.session.add(admin)
        db.session.commit()


if os.getenv("WPSECOPS_SKIP_CREATE_APP") != "1":
    app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config.get("FLASK_DEBUG", False), host="0.0.0.0", port=5000)
