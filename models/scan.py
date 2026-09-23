import uuid
from datetime import datetime
from extensions import db

class ScanHistory(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    server_id  = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False, index=True)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    status     = db.Column(db.String(20), default='pending', index=True)
    vuln_count = db.Column(db.Integer, default=0)
    raw_output = db.Column(db.Text, default='')
    duration   = db.Column(db.Float, default=0.0)
    params     = db.Column(db.JSON, nullable=True)

    results    = db.relationship('ScanResult', backref='history', lazy=True, cascade='all, delete-orphan')
    findings_list = db.relationship('ScanFinding', back_populates='history', lazy=True, cascade='all, delete-orphan')

    @property
    def interesting_count(self):
        if not self.raw_output:
            return 0
        try:
            import json
            data = json.loads(self.raw_output)
            if isinstance(data, dict):
                return len(data.get("interesting_findings", []) or [])
        except Exception:
            pass
        return 0

class ScanResult(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    scan_history_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False, index=True)
    scanner_type    = db.Column(db.String(30), nullable=False, index=True)  # 'wpscan', 'droopescan', 'nuclei'
    status          = db.Column(db.String(20), default='pending', index=True)
    vuln_count      = db.Column(db.Integer, default=0)
    raw_output      = db.Column(db.Text, default='')
    duration        = db.Column(db.Float, default=0.0)
    scanned_at      = db.Column(db.DateTime, default=datetime.utcnow)


class ScanFinding(db.Model):
    id                 = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_history_id    = db.Column(db.Integer, db.ForeignKey('scan_history.id'), nullable=False, index=True)
    component          = db.Column(db.String(50))  # 'core', 'plugin', 'theme'
    component_name     = db.Column(db.String(100))
    version            = db.Column(db.String(30))
    cve_id             = db.Column(db.String(50))
    title              = db.Column(db.String(255))
    confidence         = db.Column(db.String(30))  # 'Confirmed', 'Cross-verified', 'Likely', 'Unconfirmed', 'Review Required'
    severity           = db.Column(db.String(30))  # 'critical', 'high', 'medium', 'low' - murni dari scanner
    evidence_summary   = db.Column(db.Text)
    ai_prompt_template = db.Column(db.Text)
    ai_response        = db.Column(db.Text, nullable=True)
    manual_note        = db.Column(db.Text, nullable=True)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)

    history = db.relationship('ScanHistory', back_populates='findings_list')

