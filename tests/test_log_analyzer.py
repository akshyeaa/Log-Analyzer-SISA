```python
import pytest
import re
from backend.analyzer.log_analyzer import analyze_logs

def test_analyze_logs_empty_input():
    assert analyze_logs("") == {"insights": [], "findings": []}

def test_analyze_logs_null_input():
    assert analyze_logs(None) == {"insights": [], "findings": []}

def test_analyze_logs_empty_string_input():
    assert analyze_logs("") == {"insights": [], "findings": []}

def test_analyze_logs_single_line_input():
    input_str = "2024-01-01 12:00:00 Failed login attempt"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "failed_login"

def test_analyze_logs_multi_line_input():
    input_str = "2024-01-01 12:00:00 Failed login attempt\n2024-01-01 12:00:01 Failed login attempt"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 2
    assert result["findings"][0]["type"] == "failed_login"
    assert result["findings"][1]["type"] == "failed_login"

def test_analyze_logs_joined_logs_input():
    input_str = "[2024-01-01 12:00:00] Failed login attempt [2024-01-01 12:00:01] Failed login attempt"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 2
    assert result["findings"][0]["type"] == "failed_login"
    assert result["findings"][1]["type"] == "failed_login"

def test_analyze_logs_unauthorized_access_input():
    input_str = "2024-01-01 12:00:00 Unauthorized access attempt"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "unauthorized_access"

def test_analyze_logs_unknown_ip_login_input():
    input_str = "2024-01-01 12:00:00 Login from unknown IP"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "unknown_ip_login"

def test_analyze_logs_dangerous_command_input():
    input_str = "2024-01-01 12:00:00 rm -rf /"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "dangerous_command"

def test_analyze_logs_sql_injection_input():
    input_str = "2024-01-01 12:00:00 or '1'='1"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "sql_injection"

def test_analyze_logs_error_leak_input():
    input_str = "2024-01-01 12:00:00 Error: exception occurred"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "error_leak"

def test_analyze_logs_api_key_leak_input():
    input_str = "2024-01-01 12:00:00 AWS access key: XXXXXXXX"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "api_key_leak"

def test_analyze_logs_private_key_leak_input():
    input_str = "2024-01-01 12:00:00 -----BEGIN RSA PRIVATE KEY-----"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "private_key_leak"

def test_analyze_logs_db_credentials_leak_input():
    input_str = "2024-01-01 12:00:00 Connection string: user:password@host:port/db"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "db_credentials"

def test_analyze_logs_brute_force_attack_input():
    input_str = "2024-01-01 12:00:00 Failed login attempt\n2024-01-01 12:00:01 Failed login attempt\n2024-01-01 12:00:02 Failed login attempt"
    result = analyze_logs(input_str)
    assert len(result["insights"]) == 1
    assert len(result["findings"]) == 3
    assert result["findings"][0]["type"] == "failed_login"
    assert result["findings"][1]["type"] == "failed_login"
    assert result["findings"][2]["type"] == "failed_login"

def test_analyze_logs_invalid_input():
    with pytest.raises(Exception):
        analyze_logs(123)

def test_analyze_logs_invalid_input_type():
    with pytest.raises(Exception):
        analyze_logs([1, 2, 3])

def test_analyze_logs_invalid_input_type_dict():
    with pytest.raises(Exception):
        analyze_logs({"key": "value"})

def test_analyze_logs_max_input():
    max_input = "a" * 1000000
    result = analyze_logs(max_input)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 0

def test_analyze_logs_zero_input():
    zero_input = "0" * 1000
    result = analyze_logs(zero_input)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 0

def test_analyze_logs_negative_input():
    negative_input = "-" * 1000
    result = analyze_logs(negative_input)
    assert len(result["insights"]) == 0
    assert len(result["findings"]) == 0
```