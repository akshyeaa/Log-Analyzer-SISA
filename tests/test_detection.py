```python
import pytest
import re
from unittest.mock import patch
from backend.analyzer.detection import detect_sensitive_data, patterns, risk_levels

def test_detect_sensitive_data_empty_string():
    assert detect_sensitive_data("") == []

def test_detect_sensitive_data_none_input():
    with pytest.raises(TypeError):
        detect_sensitive_data(None)

def test_detect_sensitive_data_invalid_input_type():
    with pytest.raises(TypeError):
        detect_sensitive_data(123)

def test_detect_sensitive_data_email_pattern():
    text = "email = test@example.com"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "email"
    assert findings[0]["value"] == "test@example.com"
    assert findings[0]["risk"] == "low"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_password_pattern():
    text = "password = testpassword"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "password"
    assert findings[0]["value"] == "testpassword"
    assert findings[0]["risk"] == "critical"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_api_key_pattern():
    text = "api_key = sk-1234567890"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "api_key"
    assert findings[0]["value"] == "sk-1234567890"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_phone_pattern():
    text = "phone = 1234567890"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "phone"
    assert findings[0]["value"] == "1234567890"
    assert findings[0]["risk"] == "low"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_token_pattern():
    text = "Bearer token_value"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "token"
    assert findings[0]["value"] == "token_value"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 0

def test_detect_sensitive_data_sql_block():
    text = "INSERT INTO users (email, password) VALUES ('test@example.com', 'testpassword')"
    findings = detect_sensitive_data(text)
    assert len(findings) == 2
    assert findings[0]["type"] == "password"
    assert findings[0]["value"] == "testpassword"
    assert findings[0]["risk"] == "critical"
    assert findings[0]["line"] == 0
    assert findings[1]["type"] == "email"
    assert findings[1]["value"] == "test@example.com"
    assert findings[1]["risk"] == "low"
    assert findings[1]["line"] == 0

def test_detect_sensitive_data_api_key_in_text():
    text = "The API key is sk-1234567890"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "api_key"
    assert findings[0]["value"] == "sk-1234567890"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 0

def test_detect_sensitive_data_token_in_text():
    text = "The token is Bearer token_value"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "token"
    assert findings[0]["value"] == "token_value"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 0

def test_detect_sensitive_data_duplicate_api_key():
    text = "api_key = sk-1234567890\napi_key = sk-1234567890"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "api_key"
    assert findings[0]["value"] == "sk-1234567890"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_duplicate_token():
    text = "Bearer token_value\nBearer token_value"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "token"
    assert findings[0]["value"] == "token_value"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 0

def test_detect_sensitive_data_concurrent_api_key_detection():
    text = "api_key = sk-1234567890\napi_key = sk-9876543210"
    findings = detect_sensitive_data(text)
    assert len(findings) == 2
    assert findings[0]["type"] == "api_key"
    assert findings[0]["value"] == "sk-1234567890"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 1
    assert findings[1]["type"] == "api_key"
    assert findings[1]["value"] == "sk-9876543210"
    assert findings[1]["risk"] == "high"
    assert findings[1]["line"] == 2

def test_detect_sensitive_data_concurrent_token_detection():
    text = "Bearer token_value1\nBearer token_value2"
    findings = detect_sensitive_data(text)
    assert len(findings) == 2
    assert findings[0]["type"] == "token"
    assert findings[0]["value"] == "token_value1"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 0
    assert findings[1]["type"] == "token"
    assert findings[1]["value"] == "token_value2"
    assert findings[1]["risk"] == "high"
    assert findings[1]["line"] == 0

@patch("re.findall")
def test_detect_sensitive_data_regex_pattern_vulnerability(mock_findall):
    mock_findall.return_value = []
    text = "email = test@example.com"
    findings = detect_sensitive_data(text)
    assert len(findings) == 0

@patch("re.findall")
def test_detect_sensitive_data_regex_pattern_vulnerability_sql_block(mock_findall):
    mock_findall.return_value = []
    text = "INSERT INTO users (email, password) VALUES ('test@example.com', 'testpassword')"
    findings = detect_sensitive_data(text)
    assert len(findings) == 0

def test_detect_sensitive_data_null_pointer_exception():
    text = None
    with pytest.raises(TypeError):
        detect_sensitive_data(text)

def test_detect_sensitive_data_inconsistent_risk_level_assignment():
    text = "password = testpassword"
    findings = detect_sensitive_data(text)
    assert len(findings) == 1
    assert findings[0]["type"] == "password"
    assert findings[0]["value"] == "testpassword"
    assert findings[0]["risk"] == "critical"
    assert findings[0]["line"] == 1

def test_detect_sensitive_data_concurrency_issue_with_sets():
    text = "api_key = sk-1234567890\napi_key = sk-9876543210"
    findings = detect_sensitive_data(text)
    assert len(findings) == 2
    assert findings[0]["type"] == "api_key"
    assert findings[0]["value"] == "sk-1234567890"
    assert findings[0]["risk"] == "high"
    assert findings[0]["line"] == 1
    assert findings[1]["type"] == "api_key"
    assert findings[1]["value"] == "sk-9876543210"
    assert findings[1]["risk"] == "high"
    assert findings[1]["line"] == 2
```