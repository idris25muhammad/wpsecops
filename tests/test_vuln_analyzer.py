from unittest.mock import MagicMock
from services.vuln_analyzer import LLMClient, compute_ai_cache_key


def test_gemini_uses_header_not_query_param():
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": "Mitigasi OK"}]}}]
    }
    mock_session.post.return_value = mock_resp

    client = LLMClient(provider="gemini", api_key="SUPER_SECRET_KEY", session=mock_session)
    out = client.generate_text("halo")

    assert out == "Mitigasi OK"
    called_url = mock_session.post.call_args.args[0]
    called_headers = mock_session.post.call_args.kwargs["headers"]
    assert "SUPER_SECRET_KEY" not in called_url
    assert called_headers["x-goog-api-key"] == "SUPER_SECRET_KEY"


def test_error_sanitizes_secret_key():
    mock_session = MagicMock()
    mock_session.post.side_effect = RuntimeError("fail with ?key=MY_SECRET_123")
    client = LLMClient(provider="gemini", api_key="MY_SECRET_123", session=mock_session)
    out = client.generate_text("halo", max_retries=1)
    assert "MY_SECRET_123" not in out
    assert out.startswith("Error:")


def test_cache_key_stability():
    f = {"component": "plugin", "component_name": "akismet", "version": "5.0", "title": "XSS"}
    k1 = compute_ai_cache_key(f, "remediation", "gemini")
    k2 = compute_ai_cache_key(f, "remediation", "gemini")
    k3 = compute_ai_cache_key(f, "cve_search", "gemini")
    assert k1 == k2
    assert k1 != k3
