from sns_alert import send_security_alert

send_security_alert(
    filename="high-risk-test.txt",
    risk_level="HIGH",
    risk_score=85,
    owner_email="rrsudharsansuganthi@gmail.com",
    reason="High-risk test file detected by DataShadow."
)