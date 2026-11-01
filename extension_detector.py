"""Detect potentially executable or script-like file extensions."""
import os

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".ps1", ".sh", ".scr", ".msi", ".com", ".hta"
}


def check_suspicious_extension(file_path):
    """Return (is_suspicious: bool, extension: str)."""
    extension = os.path.splitext(os.path.basename(str(file_path)))[1].lower()
    return extension in SUSPICIOUS_EXTENSIONS, extension
