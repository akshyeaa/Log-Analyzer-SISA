```python
import pytest
from fastapi.testclient import TestClient
from main import app
from analyzer.detection import detect_sensitive_data
from analyzer.log_analyzer import analyze_logs
from analyzer.risk_engine import calculate_risk
from analyzer.ai_insights import generate_insights
from unittest.mock import patch, MagicMock
from typing import List, Optional
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

def test_analyze_no_files():
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
    assert "error" in response.json()["results"][0]

def test_analyze_file_valid_type():
    with open("test.txt", "w") as f:
        f.write("valid file content")
    with open("test.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]

def test_analyze_text():
    response = client.post("/analyze-text", data={"text": "test text"})
    assert response.status_code == 200
    assert "summary" in response.json()

def test_analyze_sql():
    response = client.post("/analyze-sql", data={"query": "test query"})
    assert response.status_code == 200
    assert "summary" in response.json()

def test_run_full_analysis_empty_input():
    assert run_full_analysis("") == {"error": "Empty input"}

def test_run_full_analysis_valid_input():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect:
        with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze:
            with patch("analyzer.risk_engine.calculate_risk") as mock_calculate:
                with patch("analyzer.ai_insights.generate_insights") as mock_generate:
                    mock_detect.return_value = []
                    mock_analyze.return_value = {"findings": [], "insights": []}
                    mock_calculate.return_value = (0, "low")
                    mock_generate.return_value = {"basic": []}
                    assert run_full_analysis("test input") == {
                        "summary": "0 sensitive items detected. Risk level: low",
                        "findings": [],
                        "risk_score": 0,
                        "risk_level": "low",
                        "insights": {"basic": []}
                    }

def test_run_full_analysis_invalid_input():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect:
        with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze:
            with patch("analyzer.risk_engine.calculate_risk") as mock_calculate:
                with patch("analyzer.ai_insights.generate_insights") as mock_generate:
                    mock_detect.side_effect = Exception("test exception")
                    mock_analyze.side_effect = Exception("test exception")
                    mock_calculate.side_effect = Exception("test exception")
                    mock_generate.side_effect = Exception("test exception")
                    assert run_full_analysis("test input") == {"error": "Empty input"}

def test_cors_configuration():
    response = client.options("/")
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert response.headers["Access-Control-Allow-Methods"] == "*"
    assert response.headers["Access-Control-Allow-Headers"] == "*"

def test_rate_limiting():
    with patch("slowapi.util.get_remote_address") as mock_get_remote_address:
        mock_get_remote_address.return_value = "test ip"
        with patch("slowapi.Limiter.limit") as mock_limit:
            mock_limit.return_value = True
            response = client.post("/analyze")
            assert response.status_code == 200
            mock_limit.assert_called_once()

def test_file_parsing_pdf():
    with open("test.pdf", "wb") as f:
        f.write(b"test pdf content")
    with open("test.pdf", "rb") as f:
        with patch("pypdf.PdfReader") as mock_pdf_reader:
            mock_pdf_reader.return_value.pages = [MagicMock(extract_text=MagicMock(return_value="test text"))]
            response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]

def test_file_parsing_docx():
    with open("test.docx", "wb") as f:
        f.write(b"test docx content")
    with open("test.docx", "rb") as f:
        with patch("docx.Document") as mock_doc:
            mock_doc.return_value.paragraphs = [MagicMock(text="test text")]
            response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]

def test_file_parsing_text():
    with open("test.txt", "w") as f:
        f.write("test text")
    with open("test.txt", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert "summary" in response.json()["results"][0]

def test_file_parsing_invalid():
    with open("test.invalid", "wb") as f:
        f.write(b"test invalid content")
    with open("test.invalid", "rb") as f:
        response = client.post("/analyze", files={"file": f})
    assert response.status_code == 200
    assert "error" in response.json()["results"][0]

def test_concurrency():
    with patch("slowapi.util.get_remote_address") as mock_get_remote_address:
        mock_get_remote_address.return_value = "test ip"
        with patch("slowapi.Limiter.limit") as mock_limit:
            mock_limit.return_value = True
            responses = []
            for _ in range(10):
                response = client.post("/analyze")
                responses.append(response)
            for response in responses:
                assert response.status_code == 200
            mock_limit.assert_called()

def test_input_validation():
    response = client.post("/analyze-text", data={"text": ""})
    assert response.status_code == 422
    response = client.post("/analyze-sql", data={"query": ""})
    assert response.status_code == 422

def test_input_sanitization():
    response = client.post("/analyze-text", data={"text": "<script>alert('test')</script>"})
    assert response.status_code == 200
    assert "<script>" not in response.json()["summary"]
    response = client.post("/analyze-sql", data={"query": "SELECT * FROM users WHERE id = 1"})
    assert response.status_code == 200
    assert "SELECT" not in response.json()["summary"]

def test_boundary_conditions():
    response = client.post("/analyze-text", data={"text": "a" * 1000})
    assert response.status_code == 200
    assert "summary" in response.json()
    response = client.post("/analyze-text", data={"text": "a" * 1001})
    assert response.status_code == 200
    assert "summary" in response.json()
    response = client.post("/analyze-text", data={"text": ""})
    assert response.status_code == 422
    response = client.post("/analyze-text", data={"text": None})
    assert response.status_code == 422

def test_mock_external_dependencies():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect:
        with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze:
            with patch("analyzer.risk_engine.calculate_risk") as mock_calculate:
                with patch("analyzer.ai_insights.generate_insights") as mock_generate:
                    mock_detect.return_value = []
                    mock_analyze.return_value = {"findings": [], "insights": []}
                    mock_calculate.return_value = (0, "low")
                    mock_generate.return_value = {"basic": []}
                    response = client.post("/analyze-text", data={"text": "test text"})
                    assert response.status_code == 200
                    assert "summary" in response.json()

def test_code_coverage():
    with patch("analyzer.detection.detect_sensitive_data") as mock_detect:
        with patch("analyzer.log_analyzer.analyze_logs") as mock_analyze:
            with patch("analyzer.risk_engine.calculate_risk") as mock_calculate:
                with patch("analyzer.ai_insights.generate_insights") as mock_generate:
                    mock_detect.return_value = []
                    mock_analyze.return_value = {"findings": [], "insights": []}
                    mock_calculate.return_value = (0, "low")
                    mock_generate.return_value = {"basic": []}
                    client.get("/")
                    client.post("/analyze")
                    client.post("/analyze-text", data={"text": "test text"})
                    client.post("/analyze-sql", data={"query": "test query"})
                    mock_detect.assert_called()
                    mock_analyze.assert_called()
                    mock_calculate.assert_called()
                    mock_generate.assert_called()
```