```python
import pytest
from unittest.mock import MagicMock
from backend.analyzer.risk_engine import calculate_risk

def test_calculate_risk_no_findings_no_log_insights():
    findings = []
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_no_findings_with_log_insights():
    findings = []
    log_insights = ["unknown ip"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 3
    assert level == "low"

def test_calculate_risk_with_findings_no_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_with_findings_with_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = ["unknown ip"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 8
    assert level == "high"

def test_calculate_risk_with_multiple_findings():
    findings = [{"risk": "critical"}, {"risk": "high"}, {"risk": "medium"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_with_multiple_log_insights():
    findings = []
    log_insights = ["unknown ip", "error", "brute-force"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 9
    assert level == "high"

def test_calculate_risk_with_invalid_findings():
    findings = "invalid"
    log_insights = None
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_with_invalid_log_insights():
    findings = []
    log_insights = "invalid"
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_with_null_findings():
    findings = None
    log_insights = None
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_with_null_log_insights():
    findings = []
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_empty_findings():
    findings = []
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_empty_log_insights():
    findings = []
    log_insights = []
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_max_score():
    findings = [{"risk": "critical"} for _ in range(10)]
    log_insights = ["unknown ip" for _ in range(10)]
    score, level = calculate_risk(findings, log_insights)
    assert score >= 10
    assert level == "critical"

def test_calculate_risk_with_negative_score():
    findings = [{"risk": "low"} for _ in range(10)]
    log_insights = ["unknown ip" for _ in range(10)]
    score, level = calculate_risk(findings, log_insights)
    assert score >= 0
    assert level != "critical"

def test_calculate_risk_with_zero_score():
    findings = []
    log_insights = []
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_invalid_risk_level():
    findings = [{"risk": "invalid"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"

def test_calculate_risk_with_invalid_log_insight():
    findings = []
    log_insights = ["invalid"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"
```