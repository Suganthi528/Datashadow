import os
import smtplib
import secrets

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load .env variables (SMTP_EMAIL, SMTP_PASSWORD, etc.)
load_dotenv()

SMTP_SERVER     = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL    = os.getenv("SMTP_EMAIL", "")
SENDER_PASSWORD = os.getenv("SMTP_PASSWORD", "")


# =========================================================
# GENERATE 6-DIGIT OTP
# =========================================================

def generate_otp():
    # secrets module is cryptographically secure — safer than random
    return f"{secrets.randbelow(1000000):06d}"


# =========================================================
# SEND OTP EMAIL
# =========================================================

def send_otp(email, otp, otp_type):

    subject = "DataShadow Security Verification"

    if otp_type == "EMAIL VERIFICATION":
        title = "DataShadow Email Verification"
        message = (
            "Welcome to DataShadow!\n\n"
            "Your email verification OTP is:\n\n"
            f"  {otp}\n\n"
            "This OTP is valid for 5 minutes.\n\n"
            "If you did not create a DataShadow account, "
            "please ignore this email."
        )
    else:
        title = "DataShadow Login Verification"
        message = (
            "DataShadow Login Security\n\n"
            "Your login verification OTP is:\n\n"
            f"  {otp}\n\n"
            "This OTP is valid for 5 minutes.\n\n"
            "Do not share this OTP with anyone."
        )

    mail = MIMEMultipart()
    mail["From"]    = SENDER_EMAIL
    mail["To"]      = email
    mail["Subject"] = subject

    body = (
        f"{title}\n\n"
        f"{message}\n\n"
        "--------------------------------\n"
        "DataShadow - Privacy-First Security\n"
        "--------------------------------"
    )
    mail.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, mail.as_string())
        server.quit()
        # Do NOT log the OTP itself — only log success
        print(f"[EMAIL] OTP email sent successfully to {email}")
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] Could not send OTP to {email}: {e}")
        return False
