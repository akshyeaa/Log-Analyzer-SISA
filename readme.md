# Log Analysis & Data Intelligence Platform

## Overview
Log Analysis & Data Intelligence Platform is a full-stack application designed to analyze logs, files, SQL queries, and live text input to detect sensitive data exposure and security risks.

The system identifies credentials such as passwords, API keys, tokens, emails, and phone numbers, evaluates risk levels, and generates both rule-based and AI-powered insights.

---

## Problem Statement

Organizations generate large volumes of logs and data where sensitive information may accidentally be exposed. Manually identifying such security risks is time-consuming and error-prone.

This project solves the problem by automating:
- Detection of sensitive data
- Risk evaluation
- Log analysis
- AI-based security insights

---

## Features

### Multi-Input Support
- Log files (.log, .txt)
- PDF files
- DOC/DOCX files
- SQL queries (file or text)
- Live chat / text input

### Sensitive Data Detection
Detects:
- Emails
- Passwords
- API Keys (sk-, gsk_, AIza, hf_)
- Tokens (Bearer, token=)
- Phone numbers

### Risk Engine
- Assigns risk levels: low, medium, high, critical
- Calculates overall risk score

### AI-Based Log Insights
Generates:
- Summary of log activity
- Detected anomalies
- Potential risks

### Log Visualization
- Line-by-line log display
- Highlighted sensitive data
- Risk-based color coding
- Navigation between breaches

### SQL Analyzer
- Detects sensitive data inside SQL queries
- Supports multi-line INSERT statements
- Works with both file upload and text input

### Live Chat Analyzer
- Real-time text analysis
- Instant detection and insights

### Security Features
- API key stored securely using environment variables
- Rate limiting implemented
- File size limits (5MB)

---

## Tech Stack

### Frontend
- Next.js
- Tailwind CSS

### Backend
- FastAPI
- Python

### AI Integration
- Groq API (llama-3.3-70b-versatile)

### Libraries Used
- python-docx
- pypdf
- slowapi
- python-dotenv

---

## Project Structure
```
Log-Analyzer-SISA/
│
├── backend/
│   ├── analyzer/
│   ├── utils/
│   ├── main.py
│   ├── requirements.txt
│   └── .env (not included in repo)
│
├── frontend/
│   ├── src/app/
│   ├── package.json
│
└── README.md
```
---

## Setup Instructions

### 1. Clone Repository

git clone https://github.com/akshyeaa/Log-Analyzer-SISA.git  
cd Log-Analyzer-SISA  

---

## Backend Setup (FastAPI)

### Step 1: Navigate to backend

cd backend  

### Step 2: Create Virtual Environment

python -m venv sisa  

Activate:

Windows:  
sisa\Scripts\activate  

Mac/Linux:  
source sisa/bin/activate  

---

### Step 3: Install Dependencies

pip install -r requirements.txt  

---

### Step 4: Create .env file

Create a `.env` file inside backend folder:

GROQ_API_KEY=your_groq_api_key_here  

---

### Step 5: Run Backend

uvicorn main:app --reload  

Backend runs at:  
http://localhost:8000  

---

## Frontend Setup (Next.js)

### Step 1: Navigate to frontend

cd frontend  

### Step 2: Install dependencies

npm install  

### Step 3: Run frontend

npm run dev  

Frontend runs at:  
http://localhost:3000  

---

## How to Use

1. Upload logs/files OR paste text  
2. Click Analyze  
3. View:
   - Detected sensitive data  
   - Risk score  
   - Insights  
   - AI analysis  

---

## Project Explanation

### Approach and Design

- Modular backend with:
  - Detection Engine  
  - Risk Engine  
  - Log Analyzer  
  - AI Insights  

- All inputs converted to text  
- Regex + structured parsing used  
- SQL handled using column-value mapping  
- AI receives masked data for safety  

---

### Challenges Faced

- Multi-line SQL parsing  
- Duplicate detection issues  
- Consistent highlighting  
- Handling large files  
- Formatting AI output  

---

### Solutions

- Used DOTALL regex for SQL  
- Implemented deduplication logic  
- Built custom highlighting system  
- Added file size limits  
- Structured AI prompts  

---

## Domain

Software Development  

---

## Demo Video

#### Link :
<Your Demo Video Link>  

---

## Live Application

### Deployed Links : 
Frontend (Vercel):  
https://log-analyzer-sisa.vercel.app/

Backend (Render):  
https://log-analyzer-sisa.onrender.com/

###### Note: The backend is deployed on Render's free tier and may go to sleep when inactive. The first request can take up to 30–60 seconds to respond. Please allow some time for the service to start.
###### Tip: Open the backend link once before using the frontend to avoid initial delay.
---

## Notes

- .env file is not included for security reasons  
- AI requires Groq API key  
- System is extendable for real-world usage  

---

## Author

U Akshay Maiya  
