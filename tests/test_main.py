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
    response = client.post("/analyze", files={"file": (None, None)})
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend working fine",
        "message": "Upload files to analyze logs"
    }

def test_analyze_file_too_large():
    with open("test_file.txt", "w") as f:
        f.write("a" * (5 * 1024 * 1024 + 1))
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.txt", f)})
    assert response.status_code == 200
    assert response.json()["results"][0]["error"] == "File too large (max 5MB)"

def test_analyze_file_invalid_type():
    with open("test_file.txt", "w") as f:
        f.write("invalid file content")
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.txt", f)})
    assert response.status_code == 200
    assert response.json()["results"][0]["error"] == "Could not parse file"

def test_analyze_file_valid_type():
    with open("test_file.txt", "w") as f:
        f.write("valid file content")
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.txt", f)})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]
    assert "findings" in response.json()["results"][0]
    assert "risk_score" in response.json()["results"][0]
    assert "risk_level" in response.json()["results"][0]
    assert "insights" in response.json()["results"][0]

def test_analyze_text():
    response = client.post("/analyze-text", data={"text": "valid text content"})
    assert response.status_code == 200
    assert "summary" in response.json()
    assert "findings" in response.json()
    assert "risk_score" in response.json()
    assert "risk_level" in response.json()
    assert "insights" in response.json()

def test_analyze_sql():
    response = client.post("/analyze-sql", data={"query": "valid sql query"})
    assert response.status_code == 200
    assert "summary" in response.json()
    assert "findings" in response.json()
    assert "risk_score" in response.json()
    assert "risk_level" in response.json()
    assert "insights" in response.json()

def test_run_full_analysis_empty_input():
    assert run_full_analysis("") == {"error": "Empty input"}

def test_run_full_analysis_valid_input():
    assert "summary" in run_full_analysis("valid input")
    assert "findings" in run_full_analysis("valid input")
    assert "risk_score" in run_full_analysis("valid input")
    assert "risk_level" in run_full_analysis("valid input")
    assert "insights" in run_full_analysis("valid input")

@patch("analyzer.detection.detect_sensitive_data")
def test_run_full_analysis_detect_sensitive_data(mock_detect_sensitive_data):
    mock_detect_sensitive_data.return_value = [{"type": "email", "value": "test@example.com"}]
    assert "summary" in run_full_analysis("valid input")
    assert "findings" in run_full_analysis("valid input")
    assert "risk_score" in run_full_analysis("valid input")
    assert "risk_level" in run_full_analysis("valid input")
    assert "insights" in run_full_analysis("valid input")

@patch("analyzer.log_analyzer.analyze_logs")
def test_run_full_analysis_analyze_logs(mock_analyze_logs):
    mock_analyze_logs.return_value = {"findings": [{"type": "log", "value": "test log"}], "insights": ["test insight"]}
    assert "summary" in run_full_analysis("valid input")
    assert "findings" in run_full_analysis("valid input")
    assert "risk_score" in run_full_analysis("valid input")
    assert "risk_level" in run_full_analysis("valid input")
    assert "insights" in run_full_analysis("valid input")

@patch("analyzer.risk_engine.calculate_risk")
def test_run_full_analysis_calculate_risk(mock_calculate_risk):
    mock_calculate_risk.return_value = (0.5, "low")
    assert "summary" in run_full_analysis("valid input")
    assert "findings" in run_full_analysis("valid input")
    assert "risk_score" in run_full_analysis("valid input")
    assert "risk_level" in run_full_analysis("valid input")
    assert "insights" in run_full_analysis("valid input")

@patch("analyzer.ai_insights.generate_insights")
def test_run_full_analysis_generate_insights(mock_generate_insights):
    mock_generate_insights.return_value = {"basic": ["test insight"]}
    assert "summary" in run_full_analysis("valid input")
    assert "findings" in run_full_analysis("valid input")
    assert "risk_score" in run_full_analysis("valid input")
    assert "risk_level" in run_full_analysis("valid input")
    assert "insights" in run_full_analysis("valid input")

def test_rate_limiting():
    for _ in range(6):
        response = client.post("/analyze", files={"file": ("test_file.txt", b"valid file content")})
        if _ < 5:
            assert response.status_code == 200
        else:
            assert response.status_code == 429

def test_cors():
    response = client.get("/", headers={"Origin": "https://example.com"})
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert response.headers["Access-Control-Allow-Methods"] == "*"
    assert response.headers["Access-Control-Allow-Headers"] == "*"

def test_env_variables():
    assert os.getenv("GROQ_API_KEY") is not None

def test_file_parsing_pdf():
    with open("test_file.pdf", "wb") as f:
        f.write(b"valid pdf content")
    with open("test_file.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.pdf", f)})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]
    assert "findings" in response.json()["results"][0]
    assert "risk_score" in response.json()["results"][0]
    assert "risk_level" in response.json()["results"][0]
    assert "insights" in response.json()["results"][0]

def test_file_parsing_docx():
    with open("test_file.docx", "wb") as f:
        f.write(b"valid docx content")
    with open("test_file.docx", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.docx", f)})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]
    assert "findings" in response.json()["results"][0]
    assert "risk_score" in response.json()["results"][0]
    assert "risk_level" in response.json()["results"][0]
    assert "insights" in response.json()["results"][0]

def test_file_parsing_text():
    with open("test_file.txt", "w") as f:
        f.write("valid text content")
    with open("test_file.txt", "rb") as f:
        response = client.post("/analyze", files={"file": ("test_file.txt", f)})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]
    assert "findings" in response.json()["results"][0]
    assert "risk_score" in response.json()["results"][0]
    assert "risk_level" in response.json()["results"][0]
    assert "insights" in response.json()["results"][0]
```