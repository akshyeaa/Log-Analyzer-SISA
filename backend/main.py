from fastapi import FastAPI, UploadFile, File, Request, Form
from typing import List, Optional
from analyzer.detection import detect_sensitive_data
from analyzer.log_analyzer import analyze_logs
from analyzer.risk_engine import calculate_risk
from analyzer.ai_insights import generate_insights
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
import os

# Load ENV
load_dotenv()

app = FastAPI()

@app.get("/")
def root():
    return {
        "status": "Backend is running successfully",
        "message": "AI Secure Log Analyzer API is active"
    }

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# RATE LIMIT
limiter = Limiter(key_func=get_remote_address)

MAX_SIZE = 5 * 1024 * 1024  # 5MB

# COMMON ANALYSIS FUNCTION
def run_full_analysis(text: str):
    groq_key = os.getenv("GROQ_API_KEY")

    if not text or not text.strip():
        return {"error": "Empty input"}

    # 1) Regex / secret detection
    findings = detect_sensitive_data(text)

    # 2) Log behavior detection
    log_analysis = analyze_logs(text)
    log_findings = log_analysis.get("findings", [])
    log_insights = log_analysis.get("insights", [])

    # 3) Merge both
    all_findings = findings + log_findings

    # 4) Risk
    score, level = calculate_risk(all_findings, log_insights)

    # 5) AI Input
    important_lines = []
    for f in all_findings:
        masked_value = str(f["value"])[:30] + "****"
        important_lines.append(f"{f['type']}: {masked_value}")

    ai_input = "\n".join(important_lines[:50]) if important_lines else text[:1000]

    # 6) AI Insights
    insights = generate_insights(all_findings, log_insights, ai_input, groq_key)

    # 7) Fallback insights if AI/basic empty
    if not insights.get("basic"):
        insights["basic"] = []

    if not insights["basic"]:
        if any(f["type"] == "email" for f in all_findings):
            insights["basic"].append("User email detected in logs")
        if any(f["type"] == "phone" for f in all_findings):
            insights["basic"].append("Phone number found in logs")
        if any(f["type"] == "password" for f in all_findings):
            insights["basic"].append("Sensitive credentials exposed")
        if any(f["type"] == "api_key" for f in all_findings):
            insights["basic"].append("API key exposed")
        if any(f["type"] == "token" for f in all_findings):
            insights["basic"].append("Authentication token exposed")

    return {
        "summary": f"{len(all_findings)} sensitive items detected. Risk level: {level}",
        "findings": all_findings,
        "risk_score": score,
        "risk_level": level,
        "insights": insights
    }


# FILE ANALYSIS
@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze(
    request: Request,
    files: Optional[List[UploadFile]] = File(None)
):
    results = []

    if files is None or len(files) == 0:
        return {
            "status": "Backend working fine",
            "message": "Upload files to analyze logs"
        }

    for file in files:
        content = await file.read()

        if len(content) > MAX_SIZE:
            results.append({
                "file_name": file.filename,
                "error": "File too large (max 5MB)"
            })
            continue

        filename = file.filename.lower()

        try:
            # PDF SUPPORT
            if filename.endswith(".pdf"):
                from pypdf import PdfReader
                import io
                reader = PdfReader(io.BytesIO(content))
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""

            # DOCX SUPPORT
            elif filename.endswith(".docx"):
                from docx import Document
                import io
                doc = Document(io.BytesIO(content))
                text = "\n".join([p.text for p in doc.paragraphs])

            # DEFAULT TEXT
            else:
                text = content.decode("utf-8", errors="ignore")

        except Exception:
            results.append({
                "file_name": file.filename,
                "error": "Could not parse file"
            })
            continue

        analysis = run_full_analysis(text)

        results.append({
            "file_name": file.filename,
            "text": text,
            "summary": analysis["summary"],
            "findings": analysis["findings"],
            "risk_score": analysis["risk_score"],
            "risk_level": analysis["risk_level"],
            "insights": analysis["insights"]
        })

    return {"results": results}


# LIVE TEXT ANALYSIS
@app.post("/analyze-text")
async def analyze_text(text: str = Form(...)):
    return run_full_analysis(text)


# SQL ANALYSIS
@app.post("/analyze-sql")
async def analyze_sql(query: str = Form(...)):
    return run_full_analysis(query)