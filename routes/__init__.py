from routes.auth import auth_bp
from routes.main import main_bp
from routes.servers import servers_bp
from routes.scan import scan_bp
from routes.history import history_bp
from routes.riset import riset_bp

def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(riset_bp)
