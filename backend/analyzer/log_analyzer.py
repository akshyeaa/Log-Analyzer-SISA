# def analyze_logs(text):
#     insights = []

#     if "ERROR" in text or "Exception" in text:
#         insights.append("System errors detected")

#     if text.lower().count("failed login") > 3:
#         insights.append("Possible brute force attack")

#     if "stack trace" in text.lower():
#         insights.append("Debug information leak detected")

#     return insights


def analyze_logs(text):
    insights = []
    lines = text.split("\n")

    failed_logins = 0

    for line in lines:
        l = line.lower()

        #  Failed login / brute force
        if "failed login" in l or "auth failed" in l or "authentication failed" in l:
            failed_logins += 1

        #  Unauthorized access
        if "unauthorized" in l or "unauthorized ssh access" in l:
            insights.append("Unauthorized access attempt detected")

        #  Unknown IP login
        if "unknown ip" in l:
            insights.append("Login from unknown IP detected")

        #  Dangerous commands
        if "rm -rf" in l or "chmod 777" in l:
            insights.append("Dangerous command execution detected")

        #  SQL Injection
        if "or '1'='1" in l or 'or "1"="1"' in l:
            insights.append("Possible SQL injection attempt detected")

        #  Debug / error leaks
        if "error" in l or "exception" in l:
            insights.append("Application error or sensitive debug information detected")

        #  API keys / secrets in logs
        if "aws_access_key" in l or "sk_test" in l or "sk_live" in l:
            insights.append("Hardcoded API key detected in logs")

        #  Private key exposure
        if "-----begin rsa private key-----" in l:
            insights.append("Private key exposure detected")

        #  Database connection leak
        if "connectionstring" in l or "password=" in l:
            insights.append("Database credentials exposed in logs")

    #  Brute force detection
    if failed_logins >= 3:
        insights.append("Multiple failed login attempts detected (possible brute-force attack)")

    return list(set(insights))