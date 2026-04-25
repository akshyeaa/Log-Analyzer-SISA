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

def test_detect_sensitive_data_non_string_input():
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
    text = "password = testpassword"
    expected = [
        {
            "type": "password",
            "value": "testpassword",
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
    text = "Bearer testtoken"
    expected = [
        {
            "type": "token",
            "value": "testtoken",
            "risk": "high",
            "line": 1
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_sql_block():
    text = """
    INSERT INTO users (email, password) VALUES ('test@example.com', 'testpassword')
    """
    expected = [
        {
            "type": "password",
            "value": "testpassword",
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
    text = "The token is Bearer testtoken"
    expected = [
        {
            "type": "token",
            "value": "testtoken",
            "risk": "high",
            "line": 0
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_multiple_lines():
    text = """
    email = test@example.com
    password = testpassword
    api_key = sk-1234567890
    phone = 1234567890
    Bearer testtoken
    """
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 2
        },
        {
            "type": "password",
            "value": "testpassword",
            "risk": "critical",
            "line": 3
        },
        {
            "type": "api_key",
            "value": "sk-1234567890",
            "risk": "high",
            "line": 4
        },
        {
            "type": "phone",
            "value": "1234567890",
            "risk": "low",
            "line": 5
        },
        {
            "type": "token",
            "value": "testtoken",
            "risk": "high",
            "line": 6
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_concurrent_access():
    import threading
    def worker(text):
        detect_sensitive_data(text)

    text = "email = test@example.com"
    threads = []
    for _ in range(10):
        t = threading.Thread(target=worker, args=(text,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    assert detect_sensitive_data(text) == [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        }
    ]

def test_detect_sensitive_data_max_input():
    text = "a" * 1000000
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_zero_length_input():
    text = ""
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_negative_length_input():
    with pytest.raises(TypeError):
        detect_sensitive_data(-1)

def test_detect_sensitive_data_invalid_pattern():
    with patch.dict(patterns, {"email": r"invalid_pattern"}):
        text = "email = test@example.com"
        assert detect_sensitive_data(text) == []
```