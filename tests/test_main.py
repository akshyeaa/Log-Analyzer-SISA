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

@pytest.fixture
def mock_detect_sensitive_data():
    with patch('analyzer.detection.detect_sensitive_data') as mock:
        yield mock

@pytest.fixture
def mock_analyze_logs():
    with patch('analyzer.log_analyzer.analyze_logs') as mock:
        yield mock

@pytest.fixture
def mock_calculate_risk():
    with patch('analyzer.risk_engine.calculate_risk') as mock:
        yield mock

@pytest.fixture
def mock_generate_insights():
    with patch('analyzer.ai_insights.generate_insights') as mock:
        yield mock

def test_root():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend is running successfully",
        "message": "AI Secure Log Analyzer API is active"
    }

def test_analyze_empty_files():
    response = client.post('/analyze')
    assert response.status_code == 200
    assert response.json() == {
        "status": "Backend working fine",
        "message": "Upload files to analyze logs"
    }

def test_analyze_file_too_large():
    with open('test.txt', 'w') as f:
        f.write('a' * (5 * 1024 * 1024 + 1))
    with open('test.txt', 'rb') as f:
        response = client.post('/analyze', files={'files': f})
    assert response.status_code == 200
    assert response.json()['results'][0]['error'] == 'File too large (max 5MB)'

def test_analyze_file_invalid_format():
    with open('test.txt', 'w') as f:
        f.write('invalid format')
    with open('test.txt', 'rb') as f:
        response = client.post('/analyze', files={'files': f})
    assert response.status_code == 200
    assert response.json()['results'][0]['error'] == 'Could not parse file'

def test_analyze_file_valid_format(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    with open('test.txt', 'w') as f:
        f.write('valid format')
    with open('test.txt', 'rb') as f:
        response = client.post('/analyze', files={'files': f})
    assert response.status_code == 200
    assert 'summary' in response.json()['results'][0]
    assert 'findings' in response.json()['results'][0]
    assert 'risk_score' in response.json()['results'][0]
    assert 'risk_level' in response.json()['results'][0]
    assert 'insights' in response.json()['results'][0]

def test_analyze_text_empty(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    response = client.post('/analyze-text', data={'text': ''})
    assert response.status_code == 200
    assert response.json() == {'error': 'Empty input'}

def test_analyze_text_valid(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    response = client.post('/analyze-text', data={'text': 'valid text'})
    assert response.status_code == 200
    assert 'summary' in response.json()
    assert 'findings' in response.json()
    assert 'risk_score' in response.json()
    assert 'risk_level' in response.json()
    assert 'insights' in response.json()

def test_analyze_sql_empty(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    response = client.post('/analyze-sql', data={'query': ''})
    assert response.status_code == 200
    assert response.json() == {'error': 'Empty input'}

def test_analyze_sql_valid(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    response = client.post('/analyze-sql', data={'query': 'valid query'})
    assert response.status_code == 200
    assert 'summary' in response.json()
    assert 'findings' in response.json()
    assert 'risk_score' in response.json()
    assert 'risk_level' in response.json()
    assert 'insights' in response.json()

def test_run_full_analysis_empty():
    assert run_full_analysis('') == {'error': 'Empty input'}

def test_run_full_analysis_valid(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    mock_detect_sensitive_data.return_value = []
    mock_analyze_logs.return_value = {'findings': [], 'insights': []}
    mock_calculate_risk.return_value = (0, 'low')
    mock_generate_insights.return_value = {'basic': []}
    assert run_full_analysis('valid text') == {
        'summary': '0 sensitive items detected. Risk level: low',
        'findings': [],
        'risk_score': 0,
        'risk_level': 'low',
        'insights': {'basic': []}
    }

def test_run_full_analysis_findings(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    mock_detect_sensitive_data.return_value = [{'type': 'email', 'value': 'test@example.com'}]
    mock_analyze_logs.return_value = {'findings': [], 'insights': []}
    mock_calculate_risk.return_value = (1, 'high')
    mock_generate_insights.return_value = {'basic': []}
    assert run_full_analysis('valid text') == {
        'summary': '1 sensitive items detected. Risk level: high',
        'findings': [{'type': 'email', 'value': 'test@example.com'}],
        'risk_score': 1,
        'risk_level': 'high',
        'insights': {'basic': ['User email detected in logs']}
    }

def test_run_full_analysis_log_findings(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    mock_detect_sensitive_data.return_value = []
    mock_analyze_logs.return_value = {'findings': [{'type': 'phone', 'value': '1234567890'}], 'insights': []}
    mock_calculate_risk.return_value = (1, 'high')
    mock_generate_insights.return_value = {'basic': []}
    assert run_full_analysis('valid text') == {
        'summary': '1 sensitive items detected. Risk level: high',
        'findings': [{'type': 'phone', 'value': '1234567890'}],
        'risk_score': 1,
        'risk_level': 'high',
        'insights': {'basic': ['Phone number found in logs']}
    }

def test_run_full_analysis_insights(mock_detect_sensitive_data, mock_analyze_logs, mock_calculate_risk, mock_generate_insights):
    mock_detect_sensitive_data.return_value = []
    mock_analyze_logs.return_value = {'findings': [], 'insights': []}
    mock_calculate_risk.return_value = (0, 'low')
    mock_generate_insights.return_value = {'basic': ['insight1', 'insight2']}
    assert run_full_analysis('valid text') == {
        'summary': '0 sensitive items detected. Risk level: low',
        'findings': [],
        'risk_score': 0,
        'risk_level': 'low',
        'insights': {'basic': ['insight1', 'insight2']}
    }
```