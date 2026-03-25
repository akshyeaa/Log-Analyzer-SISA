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
You are analyzing logs where sensitive values are masked for security.

Even if values look partially hidden (like abc***), assume they are complete in actual logs.

Return ONLY this format:

SUMMARY:
- short simple points

ANOMALIES:
- unusual or suspicious behavior

RISKS:
- possible security risks

Keep answers simple and clear.

Logs:
{text}
"""

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
            )

            ai_output = response.choices[0].message.content

            ai_output = ai_output.replace("**", "")

            formatted_lines = []
            for line in ai_output.split("\n"):
                line = line.strip()
                if line:
                    formatted_lines.append(line)

            ai_insights.append("\n".join(formatted_lines))

        except Exception as e:
            ai_insights.append(f"AI error: {str(e)}")

    return {
        "basic": list(set(insights)),
        "ai": ai_insights
    }