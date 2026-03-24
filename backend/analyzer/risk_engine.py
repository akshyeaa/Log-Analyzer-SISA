risk_score_map = {
    "password": 5,
    "api_key": 4,
    "token": 4,
    "email": 1,
    "phone": 1
}


def calculate_risk(findings):
    score = 0

    for f in findings:
        score += risk_score_map.get(f["type"], 1)

    if score >= 8:
        level = "high"
    elif score >= 4:
        level = "medium"
    else:
        level = "low"

    return score, level