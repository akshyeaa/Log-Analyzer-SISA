```python
import pytest
from unittest.mock import Mock, patch
from backend.analyzer.ai_insights import generate_insights
from typing import Dict, List

@pytest.fixture
def mock_groq_client():
    with patch('groq.Groq') as mock_groq:
        yield mock_groq

@pytest.fixture
def mock_groq_response():
    with patch('groq.Groq.chat.completions.create') as mock_response:
        yield mock_response

def test_generate_insights_no_findings_no_log_insights_no_groq_key():
    findings = []
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result == {"basic": [], "ai": []}

def test_generate_insights_password_exposed():
    findings = [{"type": "password"}]
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == ["Sensitive credentials exposed"]

def test_generate_insights_api_key_exposed():
    findings = [{"type": "api_key"}]
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == ["API key exposed"]

def test_generate_insights_token_exposed():
    findings = [{"type": "token"}]
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == ["Authentication token exposed"]

def test_generate_insights_log_insights():
    findings = []
    log_insights = ["log insight 1", "log insight 2"]
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == log_insights

def test_generate_insights_groq_key(mock_groq_client, mock_groq_response):
    findings = []
    log_insights = []
    text = "log text"
    groq_key = "groq_key"
    mock_groq_response.return_value.choices = [{"message": {"content": "SUMMARY: - summary point\nANOMALIES: - anomaly point\nRISKS: - risk point"}}}]
    result = generate_insights(findings, log_insights, text, groq_key)
    assert "SUMMARY:" in result["ai"][0]
    assert "ANOMALIES:" in result["ai"][0]
    assert "RISKS:" in result["ai"][0]

def test_generate_insights_groq_key_error(mock_groq_client, mock_groq_response):
    findings = []
    log_insights = []
    text = "log text"
    groq_key = "groq_key"
    mock_groq_response.side_effect = Exception("Groq API error")
    result = generate_insights(findings, log_insights, text, groq_key)
    assert "AI error:" in result["ai"][0]

def test_generate_insights_null_findings():
    findings = None
    log_insights = []
    text = ""
    with pytest.raises(TypeError):
        generate_insights(findings, log_insights, text)

def test_generate_insights_null_log_insights():
    findings = []
    log_insights = None
    text = ""
    with pytest.raises(TypeError):
        generate_insights(findings, log_insights, text)

def test_generate_insights_null_text():
    findings = []
    log_insights = []
    text = None
    with pytest.raises(TypeError):
        generate_insights(findings, log_insights, text)

def test_generate_insights_empty_findings():
    findings = []
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result == {"basic": [], "ai": []}

def test_generate_insights_empty_log_insights():
    findings = []
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result == {"basic": [], "ai": []}

def test_generate_insights_empty_text():
    findings = []
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result == {"basic": [], "ai": []}

def test_generate_insights_max_findings():
    findings = [{"type": "password"}] * 1000
    log_insights = []
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == ["Sensitive credentials exposed"]

def test_generate_insights_max_log_insights():
    findings = []
    log_insights = ["log insight"] * 1000
    text = ""
    result = generate_insights(findings, log_insights, text)
    assert result["basic"] == log_insights

def test_generate_insights_max_text():
    findings = []
    log_insights = []
    text = "a" * 10000
    result = generate_insights(findings, log_insights, text)
    assert result == {"basic": [], "ai": []}
```