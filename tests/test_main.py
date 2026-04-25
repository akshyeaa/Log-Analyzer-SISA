```python
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from backend.main import app, run_full_analysis
from analyzer.detection import detect_sensitive_data
from analyzer.log_analyzer import analyze_logs
from analyzer.risk_engine import calculate_risk
from analyzer.ai_insights import generate_insights
import os
import json

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend is running successfully",
        "message": "AI Secure Log Analyzer API is active"
    }

def test_analyze_empty_file():
    response = client.post("/analyze")
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend working fine",
        "message": "Upload files to analyze logs"
    }

def test_analyze_file_too_large():
    with open("test_file.txt", "w") as f:
        f.write("a" * (5 * 1024 * 1024 + 1))
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.txt"
    assert response.json()["results"][0]["error"] == "File too large (max 5MB)"

def test_analyze_file_invalid_format():
    with open("test_file.pdf", "w") as f:
        f.write("Invalid PDF content")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"
    assert response.json()["results"][0]["error"] == "Could not parse file"

def test_analyze_file_valid_pdf():
    with open("test_file.pdf", "w") as f:
        f.write("Valid PDF content")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"

def test_analyze_file_valid_docx():
    with open("test_file.docx", "w") as f:
        f.write("Valid DOCX content")
    with open("test_file.docx", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.docx"

def test_analyze_file_valid_text():
    with open("test_file.txt", "w") as f:
        f.write("Valid text content")
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.txt"

def test_analyze_text_empty():
    response = client.post("/analyze-text", data={"text": ""})
    assert response.status_code == 200
    assert response.json() == {"error": "Empty input"}

def test_analyze_text_valid():
    response = client.post("/analyze-text", data={"text": "Valid text content"})
    assert response.status_code == 200
    assert "summary" in response.json()
    assert "findings" in response.json()
    assert "risk_score" in response.json()
    assert "risk_level" in response.json()
    assert "insights" in response.json()

def test_analyze_sql_empty():
    response = client.post("/analyze-sql", data={"query": ""})
    assert response.status_code == 200
    assert response.json() == {"error": "Empty input"}

def test_analyze_sql_valid():
    response = client.post("/analyze-sql", data={"query": "Valid SQL query"})
    assert response.status_code == 200
    assert "summary" in response.json()
    assert "findings" in response.json()
    assert "risk_score" in response.json()
    assert "risk_level" in response.json()
    assert "insights" in response.json()

@patch("analyzer.detection.detect_sensitive_data")
def test_run_full_analysis_detect_sensitive_data(mock_detect_sensitive_data):
    mock_detect_sensitive_data.return_value = [{"type": "email", "value": "test@example.com"}]
    result = run_full_analysis("Test text content")
    assert result["findings"] == [{"type": "email", "value": "test@example.com"}]

@patch("analyzer.log_analyzer.analyze_logs")
def test_run_full_analysis_analyze_logs(mock_analyze_logs):
    mock_analyze_logs.return_value = {"findings": [{"type": "log", "value": "Test log content"}], "insights": []}
    result = run_full_analysis("Test text content")
    assert result["findings"] == [{"type": "log", "value": "Test log content"}]

@patch("analyzer.risk_engine.calculate_risk")
def test_run_full_analysis_calculate_risk(mock_calculate_risk):
    mock_calculate_risk.return_value = (0.5, "Medium")
    result = run_full_analysis("Test text content")
    assert result["risk_score"] == 0.5
    assert result["risk_level"] == "Medium"

@patch("analyzer.ai_insights.generate_insights")
def test_run_full_analysis_generate_insights(mock_generate_insights):
    mock_generate_insights.return_value = {"basic": ["Test insight"]}
    result = run_full_analysis("Test text content")
    assert result["insights"] == {"basic": ["Test insight"]}

def test_run_full_analysis_empty_input():
    result = run_full_analysis("")
    assert result == {"error": "Empty input"}

def test_run_full_analysis_invalid_input():
    result = run_full_analysis(None)
    assert result == {"error": "Empty input"}

def test_limiter():
    with patch("slowapi.util.get_remote_address") as mock_get_remote_address:
        mock_get_remote_address.return_value = "192.168.1.1"
        response = client.post("/analyze")
        assert response.status_code == 200
        response = client.post("/analyze")
        assert response.status_code == 429

def test_cors():
    response = client.options("/")
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert response.headers["Access-Control-Allow-Methods"] == "*"
    assert response.headers["Access-Control-Allow-Headers"] == "*"

def test_env_variables():
    assert os.getenv("GROQ_API_KEY") is not None

def test_file_parsing():
    with open("test_file.pdf", "w") as f:
        f.write("Valid PDF content")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"

def test_file_parsing_invalid_format():
    with open("test_file.pdf", "w") as f:
        f.write("Invalid PDF content")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"
    assert response.json()["results"][0]["error"] == "Could not parse file"

def test_file_parsing_empty_file():
    with open("test_file.pdf", "w") as f:
        f.write("")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"
    assert response.json()["results"][0]["error"] == "File too large (max 5MB)"

def test_file_parsing_too_large_file():
    with open("test_file.pdf", "w") as f:
        f.write("a" * (5 * 1024 * 1024 + 1))
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test_file.pdf"
    assert response.json()["results"][0]["error"] == "File too large (max 5MB)"
```