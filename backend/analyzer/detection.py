import re

patterns = {
    "email": r"email\s*=\s*[^\s]+",
    "password": r"password\s*=\s*[^\s]+",
    "api_key": r"(api_key\s*=\s*[^\s]+|sk-[a-zA-Z0-9\-]+|gsk_[a-zA-Z0-9]+|AIza[0-9A-Za-z\-_]+|hf_[a-zA-Z0-9]+)",
    "phone": r"phone\s*=\s*\d+",
    "token": r"Bearer\s+[^\s]+"
}

risk_levels = {
    "password": "critical",
    "api_key": "high",
    "token": "high",
    "email": "low",
    "phone": "low"
}


def detect_sensitive_data(text):
    findings = []
    api_seen = set()
    token_seen = set() 

    lines = text.split("\n")

    for line_no, line in enumerate(lines, start=1):
        for key, pattern in patterns.items():
            matches = re.findall(pattern, line)

            for match in matches:
                if len(str(match)) < 6:
                    continue

                if key == "api_key":
                    if match in api_seen:
                        continue
                    api_seen.add(match)

                if key == "token":
                    if match in token_seen:
                        continue
                    token_seen.add(match)

                findings.append({
                    "type": key,
                    "value": match,
                    "risk": risk_levels.get(key, "medium"),
                    "line": line_no
                })

    sql_blocks = re.findall(
        r"INSERT\s+INTO\s+\w+\s*\((.*?)\)\s*VALUES\s*\((.*?)\)",
        text,
        re.IGNORECASE | re.DOTALL
    )

    for cols, vals in sql_blocks:
        columns = [c.strip().lower() for c in cols.split(",")]
        values = [v.strip().strip("'\"") for v in vals.split(",")]

        for col, val in zip(columns, values):
            if len(val) < 4:
                continue

            if "password" in col:
                findings.append({
                    "type": "password",
                    "value": val,
                    "risk": "critical",
                    "line": 0
                })

            elif "email" in col:
                findings.append({
                    "type": "email",
                    "value": val,
                    "risk": "low",
                    "line": 0
                })

    api_matches = re.findall(
        r"(sk-[a-zA-Z0-9\-]+|gsk_[a-zA-Z0-9]+|AIza[0-9A-Za-z\-_]+|hf_[a-zA-Z0-9]+)",
        text
    )

    for match in api_matches:
        if match in api_seen:
            continue
        api_seen.add(match)

        findings.append({
            "type": "api_key",
            "value": match,
            "risk": "high",
            "line": 0
        })

    token_matches = re.findall(
        r"(?:Bearer\s+([^\s]+)|token\s*=\s*['\"]?([^\s'\"]+)['\"]?)",
        text,
        re.IGNORECASE
    )

    for match in token_matches:
        token_value = match[0] or match[1]

        if not token_value:
            continue

        if token_value in token_seen:
            continue

        token_seen.add(token_value)

        findings.append({
            "type": "token",
            "value": token_value,
            "risk": "high",
            "line": 0
        })

    return findings