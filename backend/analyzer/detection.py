# import re

# patterns = {
#     "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
#     "password": r"password\s*=\s*\w+",
#     "api_key": r"sk-[a-zA-Z0-9\-]+",
#     "phone": r"\b\d{10}\b",
#     "token": r"Bearer\s+[a-zA-Z0-9\._\-]+"
# }

# #  Risk levels per type
# risk_levels = {
#     "password": "critical",
#     "api_key": "high",
#     "token": "high",
#     "email": "low",
#     "phone": "low"
# }


# # def detect_sensitive_data(text):
# #     findings = []

# #     for key, pattern in patterns.items():
# #         matches = re.findall(pattern, text)

# #         for match in matches:
# #             findings.append({
# #                 "type": key,
# #                 "value": match,
# #                 "risk": risk_levels.get(key, "medium")
# #             })

# #     return findings

# def detect_sensitive_data(text):
#     findings = []
#     lines = text.split("\n")

#     for line_no, line in enumerate(lines, start=1):
#         for key, pattern in patterns.items():
#             matches = re.findall(pattern, line)

#             for match in matches:
#                 findings.append({
#                     "type": key,
#                     "value": match,
#                     "risk": risk_levels.get(key, "medium"),
#                     "line": line_no
#                 })

#     return findings



import re

patterns = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "password": r"password\s*=\s*\w+",
    "api_key": r"(sk-[a-zA-Z0-9\-]+|gsk_[a-zA-Z0-9]+|AIza[0-9A-Za-z\-_]+|hf_[a-zA-Z0-9]+)",
    "phone": r"\b\d{10}\b",
    "token": r"Bearer\s+[a-zA-Z0-9\._\-]+"
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
    lines = text.split("\n")

    for line_no, line in enumerate(lines, start=1):
        for key, pattern in patterns.items():
            matches = re.findall(pattern, line)

            for match in matches:
                if len(str(match)) < 6:  # avoid false positives
                    continue

                findings.append({
                    "type": key,
                    "value": match,
                    "risk": risk_levels.get(key, "medium"),
                    "line": line_no
                })

    return findings