from celery import Celery, Task
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
migrate = Migrate()


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL mode and busy timeout for SQLite to prevent lock errors."""
    module_name = type(dbapi_connection).__module__
    if "sqlite3" in module_name:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def celery_init_app(app):
    """Initialize Celery bound to the Flask app context."""
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app = Celery(app.name, task_cls=FlaskTask)
    celery_app.conf.update(
        broker_url=app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=app.config.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        task_always_eager=app.config.get("CELERY_TASK_ALWAYS_EAGER", False),
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_time_limit=1800,
        task_soft_time_limit=1700,
        task_ignore_result=True,
        worker_max_tasks_per_child=50,
        broker_connection_retry_on_startup=True,
    )
    celery_app.set_default()
    app.extensions["celery"] = celery_app
    return celery_app
