import uuid
from datetime import datetime, timezone
from extensions import db


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanHistory(db.Model):
    __tablename__ = "scan_history"
    __table_args__ = (
        db.Index("ix_scan_history_server_scanned", "server_id", "scanned_at"),
    )

    id                = db.Column(db.Integer, primary_key=True)
    server_id         = db.Column(db.Integer, db.ForeignKey("server.id"), nullable=False, index=True)
    scanned_at        = db.Column(db.DateTime, default=_utcnow, index=True)
    status            = db.Column(db.String(20), default="pending", index=True)
    vuln_count        = db.Column(db.Integer, default=0)
    interesting_count = db.Column(db.Integer, default=0)
    max_severity      = db.Column(db.String(20), nullable=True)
    risk_color        = db.Column(db.String(20), nullable=True)
    raw_output        = db.Column(db.Text, default="")
    duration          = db.Column(db.Float, default=0.0)
    params            = db.Column(db.JSON, nullable=True)

    results       = db.relationship("ScanResult", backref="history", lazy=True, cascade="all, delete-orphan")
    findings_list = db.relationship("ScanFinding", back_populates="history", lazy=True, cascade="all, delete-orphan")


class ScanResult(db.Model):
    __tablename__ = "scan_result"

    id              = db.Column(db.Integer, primary_key=True)
    scan_history_id = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=False, index=True)
    scanner_type    = db.Column(db.String(30), nullable=False, index=True)  # 'whatweb', 'wpscan', 'nuclei', 'hardening'
    status          = db.Column(db.String(20), default="pending", index=True)
    vuln_count      = db.Column(db.Integer, default=0)
    raw_output      = db.Column(db.Text, default="")
    log_text        = db.Column(db.Text, default="")
    parsed          = db.Column(db.JSON, nullable=True)
    duration        = db.Column(db.Float, default=0.0)
    started_at      = db.Column(db.DateTime, nullable=True)
    finished_at     = db.Column(db.DateTime, nullable=True)
    scanned_at      = db.Column(db.DateTime, default=_utcnow)


class ScanFinding(db.Model):
    __tablename__ = "scan_finding"
    __table_args__ = (
        db.Index("ix_scan_finding_history_conf", "scan_history_id", "confidence"),
    )

    id                 = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_history_id    = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=False, index=True)
    component          = db.Column(db.String(50))   # 'core', 'plugin', 'theme', 'wordpress', 'config'
    component_name     = db.Column(db.String(100))
    version            = db.Column(db.String(30))
    cve_id             = db.Column(db.String(50))
    title              = db.Column(db.String(255))
    confidence         = db.Column(db.String(30))   # 'Cross-verified', 'Confirmed', 'Likely', 'Unconfirmed'
    severity           = db.Column(db.String(30))   # 'critical', 'high', 'medium', 'low', 'info'
    evidence_summary   = db.Column(db.Text)
    ai_prompt_template = db.Column(db.Text)
    ai_response        = db.Column(db.Text, nullable=True)
    ai_status          = db.Column(db.String(20), default="idle")  # 'idle', 'pending', 'done', 'error'
    ai_provider        = db.Column(db.String(30), nullable=True)
    ai_generated_at    = db.Column(db.DateTime, nullable=True)
    ai_cache_key       = db.Column(db.String(64), nullable=True, index=True)
    manual_note        = db.Column(db.Text, nullable=True)
    created_at         = db.Column(db.DateTime, default=_utcnow)

    history = db.relationship("ScanHistory", back_populates="findings_list")
