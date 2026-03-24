# from fastapi import FastAPI, UploadFile, File, Form
# from typing import List
# from analyzer.detection import detect_sensitive_data
# from analyzer.log_analyzer import analyze_logs
# from analyzer.risk_engine import calculate_risk
# from analyzer.ai_insights import generate_insights
# from fastapi.middleware.cors import CORSMiddleware

# app = FastAPI()

# # ✅ CORS
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# @app.post("/analyze")
# async def analyze(
#     files: List[UploadFile] = File(...),
#     groq_key: str = Form(default=None)
# ):
#     results = []

#     for file in files:
#         content = await file.read()

#         try:
#             text = content.decode("utf-8")
#         except:
#             continue

#         # 🔥 NO CHUNKING → FIXES EVERYTHING
#         findings = detect_sensitive_data(text)
#         log_insights = analyze_logs(text)

#         # ✅ DO NOT REMOVE DUPLICATES AT ALL
#         # We WANT repeated breaches
#         all_findings = findings

#         # ✅ Risk
#         score, level = calculate_risk(all_findings)

#         # ✅ Insights
#         insights = generate_insights(
#             all_findings,
#             log_insights,
#             text,
#             groq_key
#         )

#         summary = f"{len(all_findings)} sensitive items detected. Risk level: {level}"

#         results.append({
#             "file_name": file.filename,
#             "text": text,
#             "summary": summary,
#             "findings": all_findings,
#             "risk_score": score,
#             "risk_level": level,
#             "insights": insights
#         })

#     return {"results": results}



from fastapi import FastAPI, UploadFile, File, Form, Request
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

#  Load .env
load_dotenv()

app = FastAPI()

# ✅ CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#  RATE LIMIT
limiter = Limiter(key_func=get_remote_address)


@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze(
    request: Request,
    files: List[UploadFile] = File(...)
):
    results = []

    #  GET GROQ KEY FROM ENV
    groq_key = os.getenv("GROQ_API_KEY")

    MAX_SIZE = 5 * 1024 * 1024  #  5MB

    for file in files:
        content = await file.read()

        #  FILE SIZE LIMIT
        if len(content) > MAX_SIZE:
            results.append({
                "file_name": file.filename,
                "error": "File too large (max 5MB)"
            })
            continue

        try:
            text = content.decode("utf-8")
        except:
            continue

        #  DETECTION
        findings = detect_sensitive_data(text)
        log_insights = analyze_logs(text)

        all_findings = findings  # keep ALL occurrences

        #  RISK
        score, level = calculate_risk(all_findings)

        #  IMPORTANT LINES FOR AI (OPTIMIZED)
        important_lines = []
        for f in all_findings:
            masked_value = f['value'][:3] + "***"
            important_lines.append(f"{f['type']}: {masked_value}")

        ai_input = "\n".join(important_lines[:50])

        #  INSIGHTS (AI + BASIC)
        insights = generate_insights(
            all_findings,
            log_insights,
            ai_input,   #  SEND FILTERED DATA
            groq_key
        )

        #  CLEAN AI OUTPUT (** issue fix)
        if "ai" in insights:
            insights["ai"] = [i.replace("**", "") for i in insights["ai"]]

        #  SIMPLE FALLBACK INSIGHTS (FOR SMALL FILES)
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