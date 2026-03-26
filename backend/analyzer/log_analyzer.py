import re

def analyze_logs(text):
    insights = []
    findings = []

    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()

    raw_lines = text.split("\n")
    lines = []

    for raw in raw_lines:
        raw = raw.strip()
        if not raw:
            continue

        # Split joined logs like: [2024-...] ... [2024-...] ...
        split_logs = re.split(r'(?=\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\])', raw)
        for part in split_logs:
            part = part.strip()
            if part:
                lines.append(part)

    failed_login_count = 0

    for idx, line in enumerate(lines, start=1):
        lower_line = line.lower()

        # Failed login / brute force
        if "failed login" in lower_line or "auth failed" in lower_line or "authentication failed" in lower_line:
            failed_login_count += 1
            findings.append({
                "type": "failed_login",
                "value": line,
                "risk": "high",
                "line": idx
            })

        # Unauthorized access
        if "unauthorized" in lower_line or "unauthorized ssh access" in lower_line:
            insights.append("Unauthorized access attempt detected")
            findings.append({
                "type": "unauthorized_access",
                "value": line,
                "risk": "critical",
                "line": idx
            })

        # Unknown IP login
        if "unknown ip" in lower_line:
            insights.append("Login from unknown IP detected")
            findings.append({
                "type": "unknown_ip_login",
                "value": line,
                "risk": "high",
                "line": idx
            })

        # Dangerous command execution
        if "rm -rf" in lower_line or "chmod 777" in lower_line:
            insights.append("Dangerous command execution detected")
            findings.append({
                "type": "dangerous_command",
                "value": line,
                "risk": "critical",
                "line": idx
            })

        # SQL injection
        if "or '1'='1" in lower_line or 'or "1"="1"' in lower_line:
            insights.append("Possible SQL injection attempt detected")
            findings.append({
                "type": "sql_injection",
                "value": line,
                "risk": "critical",
                "line": idx
            })

        # Error / debug leak
        if "error" in lower_line or "exception" in lower_line:
            insights.append("Application error or sensitive debug information detected")
            findings.append({
                "type": "error_leak",
                "value": line,
                "risk": "medium",
                "line": idx
            })

        # API key / secret leak
        if "aws_access_key" in lower_line or "sk_test" in lower_line or "sk_live" in lower_line:
            insights.append("Hardcoded API key detected in logs")
            findings.append({
                "type": "api_key_leak",
                "value": line,
                "risk": "high",
                "line": idx
            })

        # Private key leak
        if "-----begin rsa private key-----" in lower_line:
            insights.append("Private key exposure detected")
            findings.append({
                "type": "private_key_leak",
                "value": line,
                "risk": "critical",
                "line": idx
            })

        # DB credentials leak
        if "connectionstring" in lower_line or "password=" in lower_line:
            insights.append("Database credentials exposed in logs")
            findings.append({
                "type": "db_credentials",
                "value": line,
                "risk": "high",
                "line": idx
            })

    if failed_login_count >= 3:
        insights.append("Multiple failed login attempts detected (possible brute-force attack)")

    return {
        "insights": list(set(insights)),
        "findings": findings
    }