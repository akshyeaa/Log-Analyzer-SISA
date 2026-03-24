def analyze_logs(text):
    insights = []

    if "ERROR" in text or "Exception" in text:
        insights.append("System errors detected")

    if text.lower().count("failed login") > 3:
        insights.append("Possible brute force attack")

    if "stack trace" in text.lower():
        insights.append("Debug information leak detected")

    return insights