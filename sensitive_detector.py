import re


def detect_sensitive_data(file_path):
    detected_types = []

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read()

        if re.search(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            content
        ):
            detected_types.append("Email")

        if re.search(r'\b[6-9]\d{9}\b', content):
            detected_types.append("Phone Number")

        if re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\b', content):
            detected_types.append("Aadhaar Number")

        if re.search(r'\b(?:\d{4}[- ]?){3}\d{4}\b', content):
            detected_types.append("Card Number")

        if re.search(
            r'\b(password|passwd|secret|api[_-]?key|token)\b',
            content,
            re.IGNORECASE
        ):
            detected_types.append("Password/Secret")

    except Exception as e:
        print("Sensitive data detection error:", e)

    if detected_types:
        return True, ", ".join(detected_types)

    return False, "None"