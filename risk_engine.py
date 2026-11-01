"""Risk scoring for DataShadow.

Accepts boolean indicators or detector results such as (is_suspicious, details).
A tuple is normalized using its first element so (False, ".jpg") is NOT treated
as True just because it is a non-empty tuple.
"""


def _as_flag(value):
    """Normalize common detector outputs to a boolean flag."""
    if isinstance(value, tuple):
        # extension_detector returns (bool, extension)
        value = value[0] if value else False
    elif isinstance(value, dict):
        # Allow structured detector outputs if the caller uses them.
        value = value.get("detected", value.get("suspicious", False))
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "detected", "suspicious"}
    return bool(value)


def calculate_risk_score(
    sensitive_data=False,
    suspicious_extension=False,
    external_sharing=False,
    multiple_downloads=False,
    failed_login=False
):
    """Return (score, risk_level, reasons)."""
    sensitive_data = _as_flag(sensitive_data)
    suspicious_extension = _as_flag(suspicious_extension)
    external_sharing = _as_flag(external_sharing)
    multiple_downloads = _as_flag(multiple_downloads)
    failed_login = _as_flag(failed_login)

    score = 0
    reasons = []

    if sensitive_data:
        score += 30
        reasons.append("Sensitive data detected")

    if suspicious_extension:
        score += 20
        reasons.append("Suspicious file extension")

    if external_sharing:
        score += 25
        reasons.append("External sharing detected")

    if multiple_downloads:
        score += 15
        reasons.append("Multiple downloads detected")

    if failed_login:
        score += 10
        reasons.append("Failed login activity detected")

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level, reasons


if __name__ == "__main__":
    # Regression test: (False, ".jpg") must not add suspicious-extension points.
    score, level, reasons = calculate_risk_score(
        sensitive_data=False,
        suspicious_extension=(False, ".jpg"),
        external_sharing=False
    )
    print("JPG regression test:", score, level, reasons)
    assert score == 0
    assert level == "LOW"
    assert "Suspicious file extension" not in reasons

    score, level, reasons = calculate_risk_score(
        sensitive_data=True,
        suspicious_extension=(True, ".exe"),
        external_sharing=True
    )
    print("Suspicious file test:", score, level, reasons)
    assert score == 75
    assert level == "HIGH"
