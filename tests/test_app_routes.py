import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from extensions import db
from models import ScanFinding, ScanHistory, Server
from services.registry import SCANNERS


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_auth_required_and_login_flow(client):
    assert client.get("/dashboard").status_code == 302
    resp = client.post("/", data={"username": "admin", "password": "wrong"}, follow_redirects=False)
    assert resp.status_code == 200

    resp = client.post("/", data={"username": "admin", "password": "testpassword123"}, follow_redirects=False)
    assert resp.status_code == 302
    assert "/dashboard" in resp.location


def test_server_url_validation_rejects_injection(auth_client, app):
    # Leading dash (CLI argument injection) must be rejected
    auth_client.post("/servers", data={"name": "Bad1", "url": "--format=json"}, follow_redirects=True)
    auth_client.post("/servers", data={"name": "Bad2", "url": "ftp://example.com"}, follow_redirects=True)
    auth_client.post("/servers", data={"name": "Good", "url": "https://wp.example.com"}, follow_redirects=True)

    with app.app_context():
        servers = Server.query.all()
        assert [s.name for s in servers] == ["Good"]


def test_scan_pipeline_e2e_and_lightweight_status(auth_client, app):
    with app.app_context():
        srv = Server(name="WP Target", url="http://wp.local")
        db.session.add(srv)
        db.session.commit()
        srv_id = srv.id

    async def fake_whatweb(url, log_callback=None):
        if log_callback:
            await log_callback("WhatWeb ok")
        return {
            "status": "scanned",
            "duration": 0.1,
            "raw_output": json.dumps([{"plugins": {"WordPress": {"string": ["6.2"]}}}]),
        }

    async def fake_wpscan(url, **kwargs):
        return {
            "status": "scanned",
            "duration": 0.1,
            "raw_output": json.dumps({
                "version": {"number": "6.2"},
                "plugins": {"contact-form-7": {"version": {"number": "5.7.1"}, "outdated": True, "latest_version": "5.9"}},
                "interesting_findings": [{"url": "http://wp.local/xmlrpc.php", "to_s": "XML-RPC"}],
            }),
        }

    async def fake_nuclei(url, **kwargs):
        return {
            "status": "scanned",
            "duration": 0.1,
            "raw_output": json.dumps({
                "template-id": "cve-2023-contact-form-7-xss",
                "matched-at": "http://wp.local/wp-json",
                "info": {"name": "CF7 XSS", "severity": "high", "classification": {"cve-id": ["CVE-2023-9999"]}},
            }),
        }

    def fake_hardening(url, timeout=10):
        return {
            "target": url,
            "summary": {"PASS": 10, "FAIL": 1},
            "checks": [{"id": "dir_listing", "title": "Dir listing", "status": "FAIL", "detail": "Open", "recommendation": "Off"}],
        }

    fake_registry = {
        "whatweb": replace(SCANNERS["whatweb"], runner=fake_whatweb),
        "wpscan": replace(SCANNERS["wpscan"], runner=fake_wpscan),
        "nuclei": replace(SCANNERS["nuclei"], runner=fake_nuclei),
        "hardening": replace(SCANNERS["hardening"], runner=fake_hardening),
    }

    with patch.dict(SCANNERS, fake_registry):
        resp = auth_client.post(f"/scan/{srv_id}", json={"plugins_detection": "passive"})
        assert resp.status_code == 200
        scan_id = resp.get_json()["scan_id"]

    # Check lightweight polling endpoint
    st = auth_client.get(f"/scan-status/{scan_id}")
    assert st.status_code == 200
    st_json = st.get_json()
    assert st_json["status"] == "scanned"
    assert st_json["vuln_count"] == 2  # 1 Nuclei Confirmed + 1 Hardening FAIL
    for r in st_json["results"]:
        assert "raw_output" not in r
        assert "log_tail" in r

    # Check DB findings & severity
    with app.app_context():
        findings = ScanFinding.query.filter_by(scan_history_id=scan_id).all()
        assert len(findings) == 2
        confs = {f.component_name: f.confidence for f in findings}
        sevs = {f.component_name: f.severity for f in findings}
        assert confs["contact-form-7"] == "Confirmed"
        assert sevs["contact-form-7"] == "high"
        assert confs["dir_listing"] == "Confirmed"

    # Check pages render cleanly
    assert auth_client.get("/servers").status_code == 200
    assert auth_client.get("/history").status_code == 200
    assert auth_client.get(f"/history/{scan_id}").status_code == 200
    assert auth_client.get(f"/history/{scan_id}/workflow").status_code == 200
    assert auth_client.get("/statistics").status_code == 200
    assert auth_client.get("/system-status").status_code == 200


def test_duplicate_scan_blocked_with_409(auth_client, app):
    with app.app_context():
        srv = Server(name="Busy", url="http://busy.local")
        db.session.add(srv)
        db.session.commit()
        db.session.add(ScanHistory(server_id=srv.id, status="scanning"))
        db.session.commit()
        srv_id = srv.id

    resp = auth_client.post(f"/scan/{srv_id}", json={})
    assert resp.status_code == 409


def test_ai_analyze_and_cache_reuse(auth_client, app):
    with app.app_context():
        srv = Server(name="AI Srv", url="http://ai.local")
        db.session.add(srv)
        db.session.commit()
        sh = ScanHistory(server_id=srv.id, status="scanned")
        db.session.add(sh)
        db.session.commit()
        f1 = ScanFinding(
            scan_history_id=sh.id,
            component="plugin",
            component_name="akismet",
            version="5.0",
            title="Akismet XSS",
            confidence="Confirmed",
            severity="high",
            evidence_summary="Detected",
        )
        f2 = ScanFinding(
            scan_history_id=sh.id,
            component="plugin",
            component_name="akismet",
            version="5.0",
            title="Akismet XSS",
            confidence="Confirmed",
            severity="high",
            evidence_summary="Detected",
        )
        db.session.add_all([f1, f2])
        db.session.commit()
        f1_id, f2_id = f1.id, f2.id

    with patch("tasks.call_llm_text", return_value="Update plugin akismet") as mock_llm:
        r1 = auth_client.post(f"/history/finding/{f1_id}/analyze", json={"provider": "gemini"})
        assert r1.status_code == 200
        assert r1.get_json()["ai_response"] == "Update plugin akismet"
        assert mock_llm.call_count == 1

        # Second identical finding must hit DB cache without calling LLM again
        r2 = auth_client.post(f"/history/finding/{f2_id}/analyze", json={"provider": "gemini"})
        assert r2.status_code == 200
        assert r2.get_json()["ai_response"] == "Update plugin akismet"
        assert mock_llm.call_count == 1


def test_recover_orphan_scans(app):
    from tasks import recover_orphan_scans

    with app.app_context():
        srv = Server(name="Orphan", url="http://orphan.local")
        db.session.add(srv)
        db.session.commit()
        old_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
        sh = ScanHistory(server_id=srv.id, status="scanning", scanned_at=old_time)
        db.session.add(sh)
        db.session.commit()
        count = recover_orphan_scans(max_age_seconds=3600)
        assert count == 1
        assert db.session.get(ScanHistory, sh.id).status == "failed"


def test_riset_page_renders_five_comparative_tables(auth_client, app):
    from models import ScanResult

    with app.app_context():
        srv = Server(name="WP-Lab-1", url="http://wp1.local")
        db.session.add(srv)
        db.session.commit()

        s_seq = ScanHistory(
            server_id=srv.id, status="scanned", vuln_count=3, duration=12.0,
            risk_color="red", max_severity="high",
            params={"execution_mode": "sequential", "plugins_detection": "passive"},
        )
        s_par = ScanHistory(
            server_id=srv.id, status="scanned", vuln_count=3, duration=4.0,
            risk_color="red", max_severity="high",
            params={"execution_mode": "parallel", "plugins_detection": "passive"},
        )
        db.session.add_all([s_seq, s_par])
        db.session.commit()

        for sh in (s_seq, s_par):
            db.session.add_all([
                ScanResult(scan_history_id=sh.id, scanner_type="whatweb", status="scanned", duration=2.0,
                           parsed={"tech_stack": {"WordPress": "4.9"}, "target_info": {"wordpress_version": "4.9", "php_version": "7.2"}}),
                ScanResult(scan_history_id=sh.id, scanner_type="wpscan", status="scanned", duration=5.0,
                           parsed={"components": [{"component_name": "akismet"}], "target_info": {"wordpress_version": "4.9"}}),
                ScanResult(scan_history_id=sh.id, scanner_type="nuclei", status="scanned", duration=3.0,
                           parsed={"findings": [{"template_id": "cve-1", "severity": "high"}]}),
                ScanResult(scan_history_id=sh.id, scanner_type="hardening", status="scanned", duration=2.0,
                           parsed={"summary": {"PASS": 10, "FAIL": 2, "WARN": 1}}),
            ])
        db.session.add(ScanFinding(
            scan_history_id=s_par.id, component="plugin", component_name="akismet",
            confidence="Cross-verified", severity="high", title="Test Finding",
        ))
        db.session.commit()

    resp = auth_client.get("/riset")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Tabel 1." in html
    assert "Tabel 2." in html
    assert "Tabel 3." in html
    assert "Tabel 4." in html
    assert "Tabel 5." in html
    assert "3.0x" in html  # Speedup 12.0 / 4.0 = 3.0x
    assert "66.7%" in html  # Efisiensi (12 - 4) / 12 = 66.7%
