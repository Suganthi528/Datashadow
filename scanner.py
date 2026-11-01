"""Basic file-type categorization for DataShadow."""
import os

SAFE_FILES = {"pdf", "txt", "doc", "docx", "jpg", "jpeg", "png"}
MEDIUM_FILES = {"zip", "rar"}
HIGH_RISK_FILES = {"exe", "bat", "cmd", "sh", "ps1"}


def scan_file(filename):
    """Return (category, reason); this is a type check, not malware scanning."""
    extension = os.path.splitext(os.path.basename(str(filename)))[1].lower().lstrip(".")

    if extension in SAFE_FILES:
        return "Safe", "Trusted File"
    if extension in MEDIUM_FILES:
        return "Medium", "Compressed File"
    if extension in HIGH_RISK_FILES:
        return "High", "Executable File"
    return "Unknown", "Unsupported File Type"


if __name__ == "__main__":
    assert scan_file("photo.jpg") == ("Safe", "Trusted File")
    assert scan_file("script.exe") == ("High", "Executable File")
    print("Scanner tests passed.")
