```python
import pytest
import re
from unittest.mock import patch
from backend.analyzer.detection import detect_sensitive_data, patterns, risk_levels

def test_detect_sensitive_data_empty_input():
    assert detect_sensitive_data("") == []

def test_detect_sensitive_data_none_input():
    assert detect_sensitive_data(None) == []

def test_detect_sensitive_data_empty_string_input():
    assert detect_sensitive_data("") == []

def test_detect_sensitive_data_single_line_email():
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

def test_detect_sensitive_data_single_line_password():
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

def test_detect_sensitive_data_single_line_api_key():
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

def test_detect_sensitive_data_single_line_phone():
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

def test_detect_sensitive_data_single_line_token():
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

def test_detect_sensitive_data_multi_line():
    text = """email = test@example.com
password = testpassword
api_key = sk-1234567890
phone = 1234567890
Bearer testtoken"""
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        },
        {
            "type": "password",
            "value": "testpassword",
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
            "value": "testtoken",
            "risk": "high",
            "line": 5
        }
    ]
    assert detect_sensitive_data(text) == expected

def test_detect_sensitive_data_sql_block():
    text = """INSERT INTO users (email, password) VALUES ('test@example.com', 'testpassword')"""
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 0
        },
        {
            "type": "password",
            "value": "testpassword",
            "risk": "critical",
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

def test_detect_sensitive_data_no_matches():
    text = "This is a test with no sensitive data"
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_short_matches():
    text = "email = a"
    assert detect_sensitive_data(text) == []

def test_detect_sensitive_data_duplicate_matches():
    text = "email = test@example.com\ntoken = testtoken\ntoken = testtoken"
    expected = [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        },
        {
            "type": "token",
            "value": "testtoken",
            "risk": "high",
            "line": 2
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
        thread = threading.Thread(target=worker, args=(text,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    assert detect_sensitive_data(text) == [
        {
            "type": "email",
            "value": "test@example.com",
            "risk": "low",
            "line": 1
        }
    ]

@patch('re.findall')
def test_detect_sensitive_data_re_findall_mock(mock_findall):
    mock_findall.return_value = []
    text = "email = test@example.com"
    assert detect_sensitive_data(text) == []

@patch('re.findall')
def test_detect_sensitive_data_re_findall_mock_with_matches(mock_findall):
    mock_findall.return_value = ["test@example.com"]
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
```