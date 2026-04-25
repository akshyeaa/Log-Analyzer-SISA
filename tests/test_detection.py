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

def test_detect_sensitive_data_invalid_input():
    with pytest.raises(TypeError):
        detect_sensitive_data(123)

def test_detect_sensitive_data_email():
    text = "email = test@example.com"
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_password():
    text = "password = mysecretpassword"
    expected = [
        {
            "type": "password",
            "value": "mysecretpassword",
            "risk": "critical",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_api_key():
    text = "api_key = sk-1234567890"
    expected = [
        {
            "type": "api_key",
            "value": "sk-1234567890",
            "risk": "high",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_phone():
    text = "phone = 1234567890"
    expected = [
        {
            "type": "phone",
            "value": "1234567890",
            "risk": "low",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_token():
    text = "Bearer mytoken"
    expected = [
        {
            "type": "token",
            "value": "mytoken",
            "risk": "high",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_sql_block():
    text = """
    INSERT INTO users (email, password) VALUES ('test@example.com', 'mysecretpassword')
    """
    expected = [
        {
            "type": "password",
            "value": "mysecretpassword",
            "risk": "critical",
            "line": 0
        },
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 0
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_api_key_in_text():
    text = "The API key is sk-1234567890"
    expected = [
        {
            "type": "api_key",
            "value": "sk-1234567890",
            "risk": "high",
            "line": 0
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_token_in_text():
    text = "The token is Bearer mytoken"
    expected = [
        {
            "type": "token",
            "value": "mytoken",
            "risk": "high",
            "line": 0
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_multiple_findings():
    text = """
    email = test@example.com
    password = mysecretpassword
    api_key = sk-1234567890
    phone = 1234567890
    Bearer mytoken
    """
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        },
        {
            "type": "password",
            "value": "mysecretpassword",
            "risk": "critical",
            "line": 2
        },
        {
            "type": "api_key",
            "value": "sk-1234567890",
            "risk": "high",
            "line": 3
        },
        {
            "type": "phone",
            "value": "1234567890",
            "risk": "low",
            "line": 4
        },
        {
            "type": "token",
            "value": "mytoken",
            "risk": "high",
            "line": 5
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_no_findings():
    text = "This is a test with no sensitive data"
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_empty_lines():
    text = """
    
    """
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_long_text():
    text = "a" * 10000
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_regex_pattern_vulnerability():
    text = "email = <script>alert('XSS')</script>"
    expected = [
        {
            "type": "email",
            "value": "<script>alert('XSS')</script>",
            "risk": "low",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_null_pointer_exception():
    text = None
    with pytest.raises(TypeError):
        detect_sensitive_data(text)

def test_detect_sensitive_data_inconsistent_risk_level_assignments():
    text = "password = mysecretpassword"
    expected = [
        {
            "type": "password",
            "value": "mysecretpassword",
            "risk": "critical",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_boundary_conditions():
    text = "email = a" * 1000
    expected = [
        {
            "type": "email",
            "value": "a" * 1000,
            "risk": "low",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_mock_external_dependencies():
    with patch("re.findall") as mock_findall:
        mock_findall.return_value = []
        text = "email = test@example.com"
        expected = []
        assert detect_sensitive_data(text) == expected
```