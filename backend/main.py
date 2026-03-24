from fastapi import FastAPI, UploadFile, File, Request
from typing import List
from analyzer.detection import detect_sensitive_data
from analyzer.log_analyzer import analyze_logs
from analyzer.risk_engine import calculate_risk
from analyzer.ai_insights import generate_insights
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from dotenv import load_dotenv
import os

#  Load ENV
load_dotenv()

app = FastAPI()

#  CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#  RATE LIMIT
limiter = Limiter(key_func=get_remote_address)

MAX_SIZE = 5 * 1024 * 1024  # 5MB


#  FILE ANALYSIS
@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze(request: Request, files: List[UploadFile] = File(...)):
    results = []

    groq_key = os.getenv("GROQ_API_KEY")

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
            #  PDF SUPPORT
            if filename.endswith(".pdf"):
                from pypdf import PdfReader
                reader = PdfReader(file.file)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""

            #  DOCX SUPPORT
            elif filename.endswith(".docx"):
                from docx import Document
                doc = Document(file.file)
                text = "\n".join([p.text for p in doc.paragraphs])

            #  DEFAULT TEXT
            else:
                text = content.decode("utf-8")

        except:
            continue

        #  DETECTION
        findings = detect_sensitive_data(text)
        log_insights = analyze_logs(text)

        #  KEEP ALL OCCURRENCES
        all_findings = findings

        #  RISK
        score, level = calculate_risk(all_findings)

        #  MASK BEFORE AI
        important_lines = []
        for f in all_findings:
            masked_value = f["value"][:3] + "***"
            important_lines.append(f"{f['type']}: {masked_value}")

        ai_input = "\n".join(important_lines[:50])

        # 🤖 AI INSIGHTS
        insights = generate_insights(
            all_findings,
            log_insights,
            ai_input,
            groq_key
        )

        #  FALLBACK INSIGHTS
        if not insights["basic"]:
            if any(f["type"] == "email" for f in all_findings):
                insights["basic"].append("User email detected in logs")
            if any(f["type"] == "phone" for f in all_findings):
                insights["basic"].append("Phone number found in logs")

        summary = f"{len(all_findings)} sensitive items detected. Risk level: {level}"

        results.append({
            "file_name": file.filename,
            "text": text,
            "summary": summary,
            "findings": all_findings,
            "risk_score": score,
            "risk_level": level,
            "insights": insights
        })

    return {"results": results}


from fastapi import Form

@app.post("/analyze-text")
async def analyze_text(text: str = Form(...)):
    groq_key = os.getenv("GROQ_API_KEY")

    if not text.strip():
        return {"error": "Empty input"}

    findings = detect_sensitive_data(text)
    log_insights = analyze_logs(text)

    score, level = calculate_risk(findings)

    important_lines = []
    for f in findings:
        masked_value = f["value"][:3] + "***"
        important_lines.append(f"{f['type']}: {masked_value}")

    ai_input = "\n".join(important_lines[:50]) if important_lines else text[:500]

    insights = generate_insights(findings, log_insights, ai_input, groq_key)

    return {
        "summary": f"{len(findings)} sensitive items detected. Risk level: {level}",
        "findings": findings,
        "risk_score": score,
        "risk_level": level,
        "insights": insights
    }


@app.post("/analyze-sql")
async def analyze_sql(query: str = Form(...)):
    groq_key = os.getenv("GROQ_API_KEY")

    if not query.strip():
        return {"error": "Empty SQL input"}

    findings = detect_sensitive_data(query)
    log_insights = analyze_logs(query)

    score, level = calculate_risk(findings)

    important_lines = []
    for f in findings:
        masked_value = f["value"][:3] + "***"
        important_lines.append(f"{f['type']}: {masked_value}")

    ai_input = "\n".join(important_lines[:50]) if important_lines else query[:500]

    insights = generate_insights(findings, log_insights, ai_input, groq_key)

    return {
        "summary": f"{len(findings)} sensitive items detected. Risk level: {level}",
        "findings": findings,
        "risk_score": score,
        "risk_level": level,
        "insights": insights
    }