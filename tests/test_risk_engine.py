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

def test_calculate_risk_with_findings_and_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = ["unauthorized"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_null_findings():
    findings = None
    log_insights = None
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_null_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_empty_findings():
    findings = []
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 0
    assert level == "low"

def test_calculate_risk_empty_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = []
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_invalid_findings():
    findings = "invalid"
    log_insights = None
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_invalid_log_insights():
    findings = [{"risk": "critical"}]
    log_insights = "invalid"
    with pytest.raises(TypeError):
        calculate_risk(findings, log_insights)

def test_calculate_risk_critical_risk():
    findings = [{"risk": "critical"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_high_risk():
    findings = [{"risk": "high"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 3
    assert level == "low"

def test_calculate_risk_medium_risk():
    findings = [{"risk": "medium"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 2
    assert level == "low"

def test_calculate_risk_low_risk():
    findings = [{"risk": "low"}]
    log_insights = None
    score, level = calculate_risk(findings, log_insights)
    assert score == 1
    assert level == "low"

def test_calculate_risk_unauthorized_log_insight():
    findings = []
    log_insights = ["unauthorized"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_brute_force_log_insight():
    findings = []
    log_insights = ["brute-force"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 4
    assert level == "low"

def test_calculate_risk_sql_injection_log_insight():
    findings = []
    log_insights = ["sql injection"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_dangerous_command_log_insight():
    findings = []
    log_insights = ["dangerous command"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_private_key_log_insight():
    findings = []
    log_insights = ["private key"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_database_credentials_log_insight():
    findings = []
    log_insights = ["database credentials"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 4
    assert level == "low"

def test_calculate_risk_api_key_log_insight():
    findings = []
    log_insights = ["api key"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 4
    assert level == "low"

def test_calculate_risk_unknown_ip_log_insight():
    findings = []
    log_insights = ["unknown ip"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 3
    assert level == "low"

def test_calculate_risk_error_log_insight():
    findings = []
    log_insights = ["error"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 2
    assert level == "low"

def test_calculate_risk_debug_log_insight():
    findings = []
    log_insights = ["debug"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 2
    assert level == "low"

def test_calculate_risk_critical_level():
    findings = [{"risk": "critical"}]
    log_insights = ["unauthorized"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 10
    assert level == "critical"

def test_calculate_risk_high_level():
    findings = [{"risk": "high"}]
    log_insights = ["brute-force"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 7
    assert level == "high"

def test_calculate_risk_medium_level():
    findings = [{"risk": "medium"}]
    log_insights = ["unknown ip"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 5
    assert level == "high"

def test_calculate_risk_low_level():
    findings = [{"risk": "low"}]
    log_insights = ["error"]
    score, level = calculate_risk(findings, log_insights)
    assert score == 3
    assert level == "low"
```