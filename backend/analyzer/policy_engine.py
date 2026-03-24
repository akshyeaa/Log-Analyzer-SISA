import re

def mask_data(text):
    text = re.sub(r"password\s*=\s*\w+", "password=****", text)
    text = re.sub(r"sk-[a-zA-Z0-9]+", "sk-****", text)
    return text