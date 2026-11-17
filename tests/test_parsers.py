import json
from services.parsers import extract_json_block, parse_hardening, parse_nuclei, parse_whatweb, parse_wpscan


def test_extract_json_block_with_banner():
    raw = "Banner line\n[INFO] running\n{\"version\": {\"number\": \"6.4\"}}\n[DONE]"
    parsed = extract_json_block(raw)
    assert parsed == {"version": {"number": "6.4"}}


def test_parse_whatweb_json_and_ansi():
    raw = json.dumps([
        {
            "target": "http://example.com",
            "plugins": {
                "WordPress": {"string": ["6.4.2"]},
                "Apache": {"string": ["2.4.57"]},
                "PHP": {"string": ["8.2.1"]},
                "IP": {"string": ["127.0.0.1"]},
            },
        }
    ])
    res = parse_whatweb(raw)
    assert res["target_info"]["wordpress_version"] == "6.4.2"
    assert res["target_info"]["server"] == "Apache 2.4.57"
    assert res["target_info"]["php_version"] == "8.2.1"
    assert res["target_info"]["ip_address"] == "127.0.0.1"
    assert "WordPress: 6.4.2" in res["target_info"]["technologies"]


def test_parse_wpscan_components_and_findings():
    raw = json.dumps({
        "version": {"number": "6.2"},
        "main_theme": {"slug": "twentytwentythree", "version": {"number": "1.1"}},
        "plugins": {
            "contact-form-7": {"version": {"number": "5.7.1"}, "outdated": True, "latest_version": "5.9"},
            "*": {},
        },
        "users": {"admin": {"found_by": "Author Id Brute Forcing"}},
        "config_backups": {"http://example.com/wp-config.php.bak": {}},
        "interesting_findings": [{"url": "http://example.com/xmlrpc.php", "to_s": "XML-RPC"}],
    })
    res = parse_wpscan(raw)
    names = [c["component_name"] for c in res["components"]]
    assert "twentytwentythree" in names
    assert "contact-form-7" in names
    assert res["target_info"]["wordpress_version"] == "6.2"
    assert res["target_info"]["users_detected"] == ["admin"]
    assert len(res["target_info"]["config_backups"]) == 1
    assert len(res["target_info"]["interesting_findings"]) == 1


def test_parse_nuclei_jsonl():
    raw = "\n".join([
        "[INF] starting nuclei",
        json.dumps({
            "template-id": "CVE-2023-1234",
            "matched-at": "http://example.com/wp-json",
            "info": {
                "name": "Contact Form 7 XSS",
                "severity": "high",
                "classification": {"cve-id": ["CVE-2023-1234"]},
            },
        }),
    ])
    res = parse_nuclei(raw)
    assert len(res["findings"]) == 1
    assert res["findings"][0]["severity"] == "high"
    assert res["findings"][0]["cve_ids"] == ["CVE-2023-1234"]


def test_parse_hardening_report():
    raw = json.dumps({"summary": {"PASS": 10, "FAIL": 2}, "checks": []})
    res = parse_hardening(raw)
    assert res["summary"]["FAIL"] == 2
