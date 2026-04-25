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

def test_analyze_empty_files():
    response = client.post("/analyze")
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend working fine",
        "message": "Upload files to analyze logs"
    }

def test_analyze_file_too_large():
    with open("test.txt", "w") as f:
        f.write("a" * (5 * 1024 * 1024 + 1))
    with open("test.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["error"] == "File too large (max 5MB)"

def test_analyze_file_invalid_type():
    with open("test.txt", "w") as f:
        f.write("invalid file content")
    with open("test.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["error"] == "Could not parse file"

def test_analyze_file_pdf():
    with open("test.pdf", "w") as f:
        f.write("pdf content")
    with open("test.pdf", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test.pdf"

def test_analyze_file_docx():
    with open("test.docx", "w") as f:
        f.write("docx content")
    with open("test.docx", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test.docx"

def test_analyze_file_text():
    with open("test.txt", "w") as f:
        f.write("text content")
    with open("test.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert response.json()["results"][0]["file_name"] == "test.txt"

def test_analyze_text():
    response = client.post("/analyze-text", data={"text": "test text"})
    assert response.status_code == 200
    assert response.json()["summary"] is not None

def test_analyze_sql():
    response = client.post("/analyze-sql", data={"query": "test query"})
    assert response.status_code == 200
    assert response.json()["summary"] is not None

def test_run_full_analysis_empty_input():
    assert run_full_analysis("") == {"error": "Empty input"}

def test_run_full_analysis_invalid_input():
    assert run_full_analysis(None) == {"error": "Empty input"}

def test_run_full_analysis_valid_input():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect_sensitive_data:
        with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze_logs:
            with patch("analyzer.risk_engine.calculate_risk") as mock_calculate_risk:
                with patch("analyzer.ai_insights.generate_insights") as mock_generate_insights:
                    mock_detect_sensitive_data.return_value = []
                    mock_analyze_logs.return_value = {"findings": [], "insights": []}
                    mock_calculate_risk.return_value = (0, "low")
                    mock_generate_insights.return_value = {"basic": []}
                    assert run_full_analysis("test input") == {
                        "summary": "0 sensitive items detected. Risk level: low",
                        "findings": [],
                        "risk_score": 0,
                        "risk_level": "low",
                        "insights": {"basic": []}
                    }

def test_rate_limiting():
    with patch("slowapi.util.get_remote_address") as mock_get_remote_address:
        mock_get_remote_address.return_value = "127.0.0.1"
        for _ in range(6):
            response = client.post("/analyze")
            if _ < 5:
                assert response.status_code == 200
            else:
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

def test_detect_sensitive_data():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect_sensitive_data:
        mock_detect_sensitive_data.return_value = []
        assert detect_sensitive_data("test input") == []

def test_analyze_logs():
    with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze_logs:
        mock_analyze_logs.return_value = {"findings": [], "insights": []}
        assert analyze_logs("test input") == {"findings": [], "insights": []}

def test_calculate_risk():
    with patch("analyzer.risk_engine.calculate_risk") as mock_calculate_risk:
        mock_calculate_risk.return_value = (0, "low")
        assert calculate_risk([], []) == (0, "low")

def test_generate_insights():
    with patch("analyzer.ai_insights.generate_insights") as mock_generate_insights:
        mock_generate_insights.return_value = {"basic": []}
        assert generate_insights([], [], "", "") == {"basic": []}
```