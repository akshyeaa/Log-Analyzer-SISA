# risk_score_map = {
#     "password": 5,
#     "api_key": 4,
#     "token": 4,
#     "email": 1,
#     "phone": 1
# }


# def calculate_risk(findings):
#     score = 0

#     for f in findings:
#         score += risk_score_map.get(f["type"], 1)

#     if score >= 8:
#         level = "high"
#     elif score >= 4:
#         level = "medium"
#     else:
#         level = "low"

#     return score, level

def calculate_risk(findings, log_insights=None):
    score = 0

    # Sensitive data findings risk
    for f in findings:
        if f["risk"] == "critical":
            score += 5
        elif f["risk"] == "high":
            score += 3
        elif f["risk"] == "medium":
            score += 2
        else:
            score += 1

    # Log behavior risk
    if log_insights:
        for insight in log_insights:
            i = insight.lower()

            if "unauthorized" in i:
                score += 5
            elif "brute-force" in i or "failed login" in i:
                score += 4
            elif "sql injection" in i:
                score += 5
            elif "dangerous command" in i:
                score += 5
            elif "private key" in i:
                score += 5
            elif "database credentials" in i:
                score += 4
            elif "api key" in i:
                score += 4
            elif "unknown ip" in i:
                score += 3
            elif "error" in i or "debug" in i:
                score += 2
            else:
                score += 1

    # Final risk level
    if score >= 10:
        level = "critical"
    elif score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    return score, level