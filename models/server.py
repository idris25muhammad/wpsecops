from datetime import datetime, timezone
from extensions import db
from models.scan import ScanHistory


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Server(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    url        = db.Column(db.String(200), nullable=False)
    added_at   = db.Column(db.DateTime, default=_utcnow)
    scans      = db.relationship("ScanHistory", backref="server", lazy=True, cascade="all, delete-orphan")

    @property
    def last_status(self):
        last = ScanHistory.query.filter_by(server_id=self.id).order_by(ScanHistory.scanned_at.desc()).first()
        return last.status if last else "pending"

    @property
    def total_vulns(self):
        last = ScanHistory.query.filter_by(server_id=self.id).order_by(ScanHistory.scanned_at.desc()).first()
        return last.vuln_count if last else 0
