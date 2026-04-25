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
    log_insights = ["normal behavior"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"

def test_calculate_risk_with_findings_no_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_with_findings_and_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = ["unauthorized access"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_with_multiple_findings():
    findings = [{"risk": "critical"}, {"risk": "high"}, {"risk": "medium"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_with_multiple_log_insights():
    findings = []
    log_insights = ["unauthorized access", "brute-force attack", "sql injection"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 14
    assert level == "critical"

def test_calculate_risk_with_invalid_findings():
    findings = [{"risk": "invalid"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"

def test_calculate_risk_with_invalid_log_insights():
    findings = []
    log_insights = ["invalid insight"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"

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
    findings = [{"risk": "critical"} for _ in range(100)]
    log_insights = ["unauthorized access" for _ in range(100)]
    score, level = calculate_risk(findings, log_insights)
    assert score == 505
    assert level == "critical"

def test_calculate_risk_with_min_score():
    findings = []
    log_insights = []
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_negative_score():
    findings = [{"risk": "invalid"} for _ in range(100)]
    log_insights = ["invalid insight" for _ in range(100)]
    score, level = calculate_risk(findings, log_insights)
    assert score == 100
    assert level == "critical"

def test_calculate_risk_with_zero_score():
    findings = []
    log_insights = []
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_with_boundary_score():
    findings = [{"risk": "critical"}]
    log_insights = ["unauthorized access"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_with_critical_risk():
    findings = [{"risk": "critical"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_with_high_risk():
    findings = [{"risk": "high"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 3
    assert level == "low"

def test_calculate_risk_with_medium_risk():
    findings = [{"risk": "medium"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 2
    assert level == "low"

def test_calculate_risk_with_low_risk():
    findings = [{"risk": "low"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"
```