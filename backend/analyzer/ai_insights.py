# # import os

# # def generate_insights(findings, log_insights, text):
# #     insights = []

# #     # Rule-based fallback
# #     types = [f["type"] for f in findings]

# #     if "password" in types:
# #         insights.append("Sensitive credentials exposed")

# #     if "api_key" in types:
# #         insights.append("API key exposed")

# #     if "token" in types:
# #         insights.append("Authentication token exposed")

# #     insights.extend(log_insights)

# #     # Optional AI (Groq)
# #     GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# #     if GROQ_API_KEY:
# #         try:
# #             from groq import Groq

# #             client = Groq(api_key=GROQ_API_KEY)

# #             prompt = f"""
# #             Analyze the following logs and provide security risks and summary:
# #             {text[:2000]}
# #             """

# #             response = client.chat.completions.create(
# #                 model="llama-3.3-70b-versatile",
# #                 messages=[{"role": "user", "content": prompt}]
# #             )

# #             ai_output = response.choices[0].message.content
# #             insights.append(ai_output)

# #         except Exception:
# #             insights.append("AI analysis failed, fallback used")

# #     return insights


# def generate_insights(findings, log_insights, text, groq_key=None):
#     insights = []
#     ai_insights = []

#     types = [f["type"] for f in findings]

#     if "password" in types:
#         insights.append("Sensitive credentials exposed")

#     if "api_key" in types:
#         insights.append("API key exposed")

#     if "token" in types:
#         insights.append("Authentication token exposed")

#     insights.extend(log_insights)

#     # 🔥 GROQ AI
#     if groq_key:
#         try:
#             from groq import Groq

#             client = Groq(api_key=groq_key)

#             prompt = f"""
#             Analyze logs and give:
#             1. Summary
#             2. Security risks
#             3. Recommendations

#             Logs:
#             {text[:2000]}
#             """

#             response = client.chat.completions.create(
#                 model="llama3-8b-8192",
#                 messages=[{"role": "user", "content": prompt}]
#             )

#             ai_output = response.choices[0].message.content
#             ai_insights.append(ai_output)

#         except Exception as e:
#             ai_insights.append("AI analysis failed")

#     return {
#         "basic": list(set(insights)),
#         "ai": ai_insights
#     }

from typing import Dict, List

def generate_insights(findings, log_insights, text, groq_key=None) -> Dict:
    insights: List[str] = []
    ai_insights: List[str] = []

    types = [f["type"] for f in findings]

    if "password" in types:
        insights.append("Sensitive credentials exposed")

    if "api_key" in types:
        insights.append("API key exposed")

    if "token" in types:
        insights.append("Authentication token exposed")

    insights.extend(log_insights)

    #  GROQ AI
    if groq_key:
        try:
            from groq import Groq

            client = Groq(api_key=groq_key)

            prompt = f"""
            Analyze the following logs and give output in simple points.

            Return ONLY this format:

            SUMMARY:
            - short simple points

            ANOMALIES:
            - unusual or suspicious behavior

            RISKS:
            - possible security risks

            Keep it simple and easy to understand.

            Logs:
            {text[:1200]}
            """

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
            )

            ai_output = response.choices[0].message.content
            ai_output = ai_output.replace("**", "")
            ai_insights.append(ai_output)

        except Exception as e:
            ai_insights.append(f"AI error: {str(e)}")

    return {
        "basic": list(set(insights)),
        "ai": ai_insights
    }