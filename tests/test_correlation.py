from services.correlation import assign_confidence


def test_token_boundary_prevents_short_slug_false_positive():
    comps = [{"component_type": "plugin", "component_name": "wp", "version": "1.0"}]
    nf = {"template_id": "wordpress-xmlrpc-list", "name": "WordPress XMLRPC"}
    conf, matched = assign_confidence(nf, comps)
    assert conf == "Likely"
    assert matched is None


def test_token_boundary_confirmed_match():
    comps = [{"component_type": "plugin", "component_name": "contact-form-7", "version": "5.7.1"}]
    nf = {"template_id": "cve-2023-contact-form-7-xss", "name": "Contact Form 7 XSS"}
    conf, matched = assign_confidence(nf, comps)
    assert conf == "Confirmed"
    assert matched["component_name"] == "contact-form-7"


def test_cross_verified_when_version_matches():
    comps = [{"component_type": "plugin", "component_name": "elementor", "version": "3.12.0"}]
    nf = {
        "template_id": "elementor-version-disclosure",
        "name": "Elementor Exposure",
        "extracted_results": ["3.12.0"],
    }
    conf, matched = assign_confidence(nf, comps)
    assert conf == "Cross-verified"
    assert matched["component_name"] == "elementor"
