import os
from flask import Flask
from werkzeug.security import generate_password_hash
from config import Config
from extensions import db, login_manager
from models import Admin
from routes import register_routes

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    cache_dir = app.config.get("CACHE_DIR", "ai_cache")
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(Admin, int(user_id))

    register_routes(app)

    with app.app_context():
        init_db()

    return app


def _migrate_schema():
    """Migrasi ringan: tambahkan kolom baru yang belum ada di DB lama."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    if "scan_history" in tables:
        cols = {c["name"] for c in inspector.get_columns("scan_history")}
        if "params" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN params JSON"))


def init_db():
    db.create_all()
    _migrate_schema()

    if not Admin.query.first():
        admin = Admin(
            username="admin",
            password=generate_password_hash("admin123")
        )
        db.session.add(admin)
        db.session.commit()


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)