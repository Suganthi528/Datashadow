import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from database import get_db_connection

from scanner import scan_file
from activity_logger import log_activity
from audit_logger import log_security_event
from sensitive_detector import detect_sensitive_data
from file_hash import calculate_file_hash
from integrity_monitor import check_file_integrity
from extension_detector import check_suspicious_extension
from risk_engine import calculate_risk_score
from provenance_manager import log_provenance

from blocking.blocking import (
    block_user,
    is_user_blocked,
    unblock_user
)

# ============================================================
# USER BEHAVIOR ANALYTICS
# ============================================================

from user_behavior import analyze_user_behavior
from incident_manager import create_security_incident
from automated_response import automated_incident_response
from custody_manager import log_custody_action
from aws_s3_manager import upload_file_to_s3


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = "datashadow_secret_key"

MAX_FAILED_ATTEMPTS = 3


# ============================================================
# ALERT FUNCTION
# ============================================================

def send_alert(email, filename, risk_score):

    print(
        f"ALERT: High risk file detected | "
        f"Email: {email} | "
        f"File: {filename} | "
        f"Risk Score: {risk_score}"
    )


# ============================================================
# AUTOMATIC UBA ALERT
# ============================================================

def process_uba(username, email, activity_type):

    try:
        # Record the user activity using the existing UBA module.
        # The updated user_behavior.py also performs Insider Threat Detection.
        result = analyze_user_behavior(
            username,
            email,
            activity_type
        )

        activity_count = 0
        risk_level = "LOW"
        insider_threat = False
        incident_created = False

        if isinstance(result, dict):
            activity_count = result.get("activity_count", 0)
            risk_level = str(
                result.get("risk_level", "LOW")
            ).upper()
            insider_threat = bool(
                result.get("insider_threat", False)
            )
            incident_created = bool(
                result.get("incident_created", False)
            )
        else:
            # Backward-compatible fallback for older UBA results.
            conn = get_db_connection()

            if conn is not None:
                cursor = conn.cursor(dictionary=True)

                cursor.execute(
                    """
                    SELECT activity_count, risk_level
                    FROM user_behavior_logs
                    WHERE email=%s
                    AND activity_type=%s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (email, activity_type)
                )

                latest = cursor.fetchone()

                cursor.close()
                conn.close()

                if latest:
                    activity_count = latest.get(
                        "activity_count",
                        0
                    )

                    risk_level = str(
                        latest.get(
                            "risk_level",
                            "LOW"
                        )
                    ).upper()

        # The updated user_behavior.py is responsible for creating
        # the INSIDER_THREAT incident. We only record the audit event
        # here so that duplicate incidents are not created.
        if risk_level in ["HIGH", "CRITICAL"]:

            description = (
                f"UBA detected suspicious behavior: {activity_type} | "
                f"Activity count: {activity_count} | "
                f"Risk: {risk_level}"
            )

            print("====================================")
            print("UBA ALERT")
            print(description)
            print("Insider Threat:", insider_threat)
            print("Incident Created:", incident_created)
            print("====================================")

            log_security_event(
                username,
                email,
                "UBA_ALERT",
                description,
                risk_level,
                request.remote_addr
            )

        return {
            "activity_count": activity_count,
            "risk_level": risk_level,
            "insider_threat": insider_threat,
            "incident_created": incident_created
        }

    except Exception as e:

        print("UBA alert processing error:", e)

        return {
            "activity_count": 0,
            "risk_level": "LOW",
            "insider_threat": False,
            "incident_created": False
        }



# ============================================================
# RISK SCORE CONVERSION
# ============================================================

def get_numeric_risk_score(risk_result):

    try:

        if isinstance(risk_result, (tuple, list)):

            if len(risk_result) > 0:

                risk_result = risk_result[0]

            else:

                return 0

        return int(risk_result)

    except Exception as e:

        print(
            "Risk score conversion error:",
            e
        )

        return 0


# ============================================================
# HOME / REGISTRATION
# ============================================================

@app.route("/", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # CHECK EMPTY FIELDS
        # ----------------------------------------------------

        if not username or not email or not password:

            return "Please fill all fields."

        # ----------------------------------------------------
        # DATABASE CONNECTION
        # ----------------------------------------------------

        conn = get_db_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # CHECK EXISTING USER
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE email=%s
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            cursor.close()
            conn.close()

            return "Email already registered. Please login."

        # ----------------------------------------------------
        # PASSWORD HASHING
        # ----------------------------------------------------

        hashed_password = generate_password_hash(
            password
        )

        # ----------------------------------------------------
        # CREATE USER
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password
            )
            VALUES (%s, %s, %s)
            """,
            (
                username,
                email,
                hashed_password
            )
        )

        conn.commit()

        cursor.close()
        conn.close()

        # ----------------------------------------------------
        # SECURITY LOG
        # ----------------------------------------------------

        log_security_event(
            session.get(
                "username",
                "Unknown"
            ),
            email,
            "REGISTRATION",
            "New user registered successfully",
            "SUCCESS",
            request.remote_addr
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # DATABASE CONNECTION
        # ----------------------------------------------------

        conn = get_db_connection()

        cursor = conn.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE email=%s
            """,
            (email,)
        )

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        # ----------------------------------------------------
        # USER NOT FOUND
        # ----------------------------------------------------

        if not user:

            log_security_event(
                session.get(
                    "username",
                    "Unknown"
                ),
                email,
                "LOGIN",
                "Login attempted with unknown email",
                "FAILED",
                request.remote_addr
            )

            return "Invalid email or password."

        # ----------------------------------------------------
        # CHECK BLOCKED USER
        # ----------------------------------------------------

        if is_user_blocked(email):

            log_security_event(
                session.get(
                    "username",
                    "Unknown"
                ),
                email,
                "LOGIN",
                "Blocked user attempted login",
                "BLOCKED",
                request.remote_addr
            )

            return (
                "Your account is blocked. "
                "Please contact administrator."
            )

        # ----------------------------------------------------
        # CHECK PASSWORD
        # ----------------------------------------------------

        if check_password_hash(
            user["password"],
            password
        ):

            # Reset failed attempts

            session["failed_attempts"] = 0

            # ------------------------------------------------
            # AUTHENTICATION SUCCESS
            # ------------------------------------------------

            session["authenticated"] = True

            session["email"] = email

            session["username"] = user["username"]

            # ------------------------------------------------
            # ACTIVITY LOG
            # ------------------------------------------------

            log_activity(
                user["username"],
                email,
                "LOGIN",
                "User logged in successfully"
            )

            # ------------------------------------------------
            # USER BEHAVIOR ANALYTICS
            # ------------------------------------------------

            process_uba(
                user["username"],
                email,
                "LOGIN"
            )

            # ------------------------------------------------
            # SECURITY AUDIT
            # ------------------------------------------------

            log_security_event(
                session.get(
                    "username",
                    "Unknown"
                ),
                email,
                "LOGIN",
                "User successfully logged in",
                "SUCCESS",
                request.remote_addr
            )

            return redirect(
                url_for("dashboard")
            )

        # ====================================================
        # WRONG PASSWORD
        # ====================================================

        failed_attempts = session.get(
            "failed_attempts",
            0
        )

        failed_attempts += 1

        session["failed_attempts"] = failed_attempts

        # ----------------------------------------------------
        # SECURITY LOG
        # ----------------------------------------------------

        log_security_event(
            session.get(
                "username",
                "Unknown"
            ),
            email,
            "LOGIN",
            f"Incorrect password attempt {failed_attempts}",
            "FAILED",
            request.remote_addr
        )

        # ----------------------------------------------------
        # USER BEHAVIOR ANALYTICS + AUTOMATIC ALERT
        # ----------------------------------------------------

        process_uba(
            user["username"],
            email,
            "FAILED_LOGIN"
        )

        # ----------------------------------------------------
        # BLOCK USER AFTER 3 ATTEMPTS
        # ----------------------------------------------------

        if failed_attempts >= MAX_FAILED_ATTEMPTS:

            block_user(
                user["username"],
                email,
                "Blocked after 3 failed login attempts"
            )

            log_activity(
                user["username"],
                email,
                "ACCOUNT_BLOCKED",
                "User blocked after multiple failed login attempts"
            )

            log_security_event(
                session.get(
                    "username",
                    "Unknown"
                ),
                email,
                "ACCOUNT_SECURITY",
                "Account blocked after 3 failed login attempts",
                "ACCOUNT_BLOCKED",
                request.remote_addr
            )

            # ----------------------------------------------------
            # USER BEHAVIOR ANALYTICS + AUTOMATIC ALERT
            # ----------------------------------------------------

            process_uba(
                user["username"],
                email,
                "ACCOUNT_BLOCKED"
            )

            session.clear()

            return (
                "Your account has been blocked "
                "after 3 failed login attempts."
            )

        remaining = (
            MAX_FAILED_ATTEMPTS -
            failed_attempts
        )

        return (
            f"Invalid email or password. "
            f"Attempts remaining: {remaining}"
        )

    return render_template(
        "login.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    # --------------------------------------------------------
    # CHECK LOGIN
    # --------------------------------------------------------

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    email = session.get("email")

    # --------------------------------------------------------
    # DATABASE CONNECTION
    # --------------------------------------------------------

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    # --------------------------------------------------------
    # GET CURRENT USER FILES
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE owner_email=%s
        ORDER BY id DESC
        """,
        (email,)
    )

    files = cursor.fetchall()

    cursor.close()
    conn.close()

    # --------------------------------------------------------
    # SEND FILES TO DASHBOARD
    # --------------------------------------------------------

    return render_template(
        "dashboard.html",
        reports=files,
        username=session.get("username")
    )


# ============================================================
# FILE UPLOAD
# ============================================================

@app.route("/upload", methods=["GET", "POST"])
def upload():

    # --------------------------------------------------------
    # CHECK LOGIN
    # --------------------------------------------------------

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    # --------------------------------------------------------
    # GET REQUEST
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "upload.html"
        )

    email = session.get("email")

    username = session.get("username")

    # --------------------------------------------------------
    # CHECK FILE
    # --------------------------------------------------------

    if "file" not in request.files:

        return "No file selected."

    file = request.files["file"]

    if file.filename == "":

        return "No file selected."

    # --------------------------------------------------------
    # SECURE FILE NAME
    # --------------------------------------------------------

    filename = secure_filename(
        file.filename
    )

    # --------------------------------------------------------
    # UPLOAD FOLDER
    # --------------------------------------------------------

    upload_folder = os.path.join(
        app.root_path,
        "uploads"
    )

    os.makedirs(
        upload_folder,
        exist_ok=True
    )

    filepath = os.path.join(
        upload_folder,
        filename
    )

    # --------------------------------------------------------
    # SAVE FILE
    # --------------------------------------------------------

    file.save(filepath)

    # ========================================================
    # FILE SCANNING
    # ========================================================

    try:

        scan_result = scan_file(
            filepath
        )

    except Exception as e:

        print(
            "Scanner error:",
            e
        )

        scan_result = "SCAN_ERROR"

    # ========================================================
    # SENSITIVE DATA DETECTION
    # ========================================================

    try:

        sensitive_result = detect_sensitive_data(
            filepath
        )

    except Exception as e:

        print(
            "Sensitive detection error:",
            e
        )

        sensitive_result = {}

    # ========================================================
    # FILE HASH
    # ========================================================

    try:

        file_hash = calculate_file_hash(
            filepath
        )

    except Exception as e:

        print(
            "Hash error:",
            e
        )

        file_hash = ""

    # ========================================================
    # SUSPICIOUS EXTENSION
    # ========================================================

    try:

        extension_result = check_suspicious_extension(
            filename
        )

    except Exception as e:

        print(
            "Extension detection error:",
            e
        )

        extension_result = False

    # ========================================================
    # RISK SCORE
    # ========================================================

    try:

        raw_risk_score = calculate_risk_score(
            scan_result,
            sensitive_result,
            extension_result
        )

        # DEBUG: print the inputs and output from each analysis module.
        # These messages help identify why ordinary files are marked High.
        print("========== DATASHADOW RISK DEBUG ==========")
        print("Filename:", filename)
        print("Scanner result:", repr(scan_result))
        print("Sensitive-data result:", repr(sensitive_result))
        print("Suspicious-extension result:", repr(extension_result))
        print("Raw risk-engine result:", repr(raw_risk_score))

        risk_score = get_numeric_risk_score(
            raw_risk_score
        )

        print("Numeric risk score:", risk_score)
        print("===========================================")

    except Exception as e:

        print(
            "Risk engine error:",
            e
        )

        risk_score = 0

    # ========================================================
    # RISK SCORE 0-100
    # ========================================================

    if risk_score < 0:

        risk_score = 0

    if risk_score > 100:

        risk_score = 100

    # ========================================================
    # SENSITIVE DATA VALUES
    # ========================================================

    sensitive_data = "NO"

    sensitive_types = ""

    if isinstance(
        sensitive_result,
        dict
    ):

        if sensitive_result.get(
            "sensitive"
        ):

            sensitive_data = "YES"

        sensitive_types = str(
            sensitive_result.get(
                "types",
                ""
            )
        )

    # ========================================================
    # FILE TYPE
    # ========================================================

    file_type = (
        os.path.splitext(filename)[1]
        .replace(".", "")
        .upper()
    )

    if not file_type:

        file_type = "UNKNOWN"

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if risk_score >= 90:

        risk_level = "Critical"

    elif risk_score >= 70:

        risk_level = "High"

    elif risk_score >= 40:

        risk_level = "Medium"

    else:

        risk_level = "Safe"

    # ========================================================
    # ALERT MESSAGE
    # ========================================================

    if risk_level == "Critical":

        alert_message = "Critical Risk Detected"

    elif risk_level == "High":

        alert_message = "High Risk Detected"

    elif risk_level == "Medium":

        alert_message = "Medium Risk"

    else:

        alert_message = "No Major Risk"

    # ========================================================
    # SUSPICIOUS EXTENSION
    # ========================================================

    if extension_result:

        suspicious_extension = "YES"

    else:

        suspicious_extension = "NO"

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    conn = get_db_connection()

    cursor = conn.cursor()

    # --------------------------------------------------------
    # FILE SIZE
    # --------------------------------------------------------

    file_size = os.path.getsize(
        filepath
    )

    # --------------------------------------------------------
    # RISK REASONS
    # --------------------------------------------------------

    risk_reasons = str(
        scan_result
    )

    if sensitive_data == "YES":

        risk_reasons += (
            f" | Sensitive data: "
            f"{sensitive_types}"
        )

    if suspicious_extension == "YES":

        risk_reasons += (
            " | Suspicious file extension detected"
        )

    # ========================================================
    # SAVE FILE
    # ========================================================

    cursor.execute(
        """
        INSERT INTO files
        (
            filename,
            filepath,
            owner_email,
            file_size,
            file_type,
            risk_score,
            risk_level,
            risk_reasons,
            file_hash
        )
        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """,
        (
            filename,
            filepath,
            email,
            file_size,
            file_type,
            risk_score,
            risk_level,
            risk_reasons,
            file_hash
        )
    )

    file_id = cursor.lastrowid

    # ========================================================
    # SAVE FILE ANALYSIS
    # ========================================================

    cursor.execute(
        """
        INSERT INTO file_analysis
        (
            filename,
            owner_email,
            risk_level,
            reason
        )
        VALUES
        (%s, %s, %s, %s)
        """,
        (
            filename,
            email,
            risk_level,
            risk_reasons
        )
    )

    # ========================================================
    # SAVE ALERT
    # ========================================================

    cursor.execute(
        """
        INSERT INTO alerts
        (
            filename,
            owner_email,
            risk_level,
            alert_message
        )
        VALUES
        (%s, %s, %s, %s)
        """,
        (
            filename,
            email,
            risk_level,
            alert_message
        )
    )

    # ========================================================
    # SAVE SENSITIVE DATA
    # ========================================================

    cursor.execute(
        """
        INSERT INTO sensitive_data_logs
        (
            file_id,
            filename,
            owner_email,
            sensitive_data,
            sensitive_types
        )
        VALUES
        (%s, %s, %s, %s, %s)
        """,
        (
            file_id,
            filename,
            email,
            sensitive_data,
            sensitive_types
        )
    )

    # ========================================================
    # SAVE SUSPICIOUS EXTENSION
    # ========================================================

    extension = os.path.splitext(
        filename
    )[1].lower()

    cursor.execute(
        """
        INSERT INTO suspicious_extension_logs
        (
            file_id,
            filename,
            owner_email,
            extension,
            risk_level
        )
        VALUES
        (%s, %s, %s, %s, %s)
        """,
        (
            file_id,
            filename,
            email,
            extension,
            risk_level
            if suspicious_extension == "YES"
            else "Safe"
        )
    )

    # ========================================================
    # COMMIT DATABASE
    # ========================================================

    conn.commit()

    # ========================================================
    # AWS S3 CLOUD STORAGE INTEGRATION
    # ========================================================

    s3_upload_success = upload_file_to_s3(
        filepath,
        filename
    )

    if s3_upload_success:

        print("====================================")
        print("AWS S3 FILE UPLOAD COMPLETED")
        print("File:", filename)
        print("====================================")

    else:

        print("====================================")
        print("AWS S3 FILE UPLOAD FAILED")
        print("Local DataShadow upload will continue.")
        print("File:", filename)
        print("====================================")

    # CHAIN OF CUSTODY - EVIDENCE CREATED
    log_custody_action(
        evidence_id=file_id,
        action="CREATED",
        username=username,
        description=f"File evidence created during upload: {filename}"
    )

    cursor.close()
    conn.close()

    # ========================================================
    # ACTIVITY LOG
    # ========================================================

    log_activity(
        username,
        email,
        "FILE_UPLOAD",
        f"Uploaded file: {filename}"
    )

    # ========================================================
    # USER BEHAVIOR ANALYTICS
    # ========================================================

    process_uba(
        username,
        email,
        "FILE_UPLOAD"
    )

    # ========================================================
    # SECURITY AUDIT
    # ========================================================

    log_security_event(
        session.get(
            "username",
            "Unknown"
        ),
        email,
        "FILE_UPLOAD",
        f"File uploaded: {filename}",
        "SUCCESS",
        request.remote_addr
    )

    # ========================================================
    # HIGH RISK ALERT + MODULE 25 INSIDER THREAT INDICATOR
    # ========================================================

    if risk_score >= 70:

        send_alert(
            email,
            filename,
            risk_score
        )

        risk_description = (
            f"High risk file detected: {filename}, "
            f"score={risk_score}, risk_level={risk_level}"
        )

        log_security_event(
            session.get(
                "username",
                "Unknown"
            ),
            email,
            "RISK_ANALYSIS",
            risk_description,
            "HIGH_RISK",
            request.remote_addr
        )

        # ----------------------------------------------------
        # MODULE 25
        # Treat a HIGH/CRITICAL uploaded file as an insider-threat
        # indicator in this project. This makes the file-risk
        # engine contribute to the Insider Threat module.
        # ----------------------------------------------------

        insider_description = (
            f"Insider threat indicator detected during file upload. "
            f"User {username} uploaded {filename}. "
            f"File risk score: {risk_score}. "
            f"File risk level: {risk_level}."
        )

        incident_risk = (
            "CRITICAL"
            if risk_score >= 90
            else "HIGH"
        )

        incident_created = create_security_incident(
            incident_type="INSIDER_THREAT",
            description=insider_description,
            risk_level=incident_risk,
            username=username,
            email=email
        )

        print("====================================")
        print("INSIDER THREAT INDICATOR")
        print("Username:", username)
        print("File:", filename)
        print("Risk Score:", risk_score)
        print("Risk Level:", risk_level)
        print("Incident Created:", incident_created)
        print("====================================")

        # ====================================================
        # MODULE 26
        # AUTOMATED INCIDENT RESPONSE
        # ====================================================

        automated_response = automated_incident_response(
            incident_type="INSIDER_THREAT",
            description=insider_description,
            risk_level=incident_risk,
            username=username,
            email=email
        )

        print("====================================")
        print("AUTOMATED INCIDENT RESPONSE RESULT")
        print("Response:", automated_response)
        print("====================================")

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DOWNLOAD FILE
# ============================================================

@app.route("/download/<int:file_id>")
def download(file_id):

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    email = session.get("email")

    username = session.get("username")

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    # --------------------------------------------------------
    # USER CAN DOWNLOAD ONLY THEIR OWN FILE
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE id=%s
        AND owner_email=%s
        """,
        (
            file_id,
            email
        )
    )

    file = cursor.fetchone()

    cursor.close()
    conn.close()

    if not file:

        return "File not found or access denied."

    filename = file["filename"]

    # --------------------------------------------------------
    # ACTIVITY LOG
    # --------------------------------------------------------

    log_activity(
        username,
        email,
        "FILE_DOWNLOAD",
        f"Downloaded file: {filename}"
    )

    # --------------------------------------------------------
    # USER BEHAVIOR ANALYTICS
    # --------------------------------------------------------

    process_uba(
        username,
        email,
        "FILE_DOWNLOAD"
    )

    # --------------------------------------------------------
    # SECURITY AUDIT
    # --------------------------------------------------------

    log_security_event(
        session.get(
            "username",
            "Unknown"
        ),
        email,
        "FILE_DOWNLOAD",
        f"File downloaded: {filename}",
        "SUCCESS",
        request.remote_addr
    )

    upload_folder = os.path.join(
        app.root_path,
        "uploads"
    )

    return send_from_directory(
        upload_folder,
        filename,
        as_attachment=True
    )


# ============================================================
# SHARE FILE
# ============================================================

@app.route(
    "/share/<int:file_id>",
    methods=["GET", "POST"]
)
def share_file(file_id):

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    email = session.get("email")

    username = session.get("username")

    # --------------------------------------------------------
    # GET REQUEST
    # --------------------------------------------------------

    if request.method == "GET":

        return """
        <h2>Share File</h2>

        <form method="POST">

            <label>Enter Email:</label>

            <input
                type="email"
                name="shared_email"
                required
            >

            <button type="submit">
                Share
            </button>

        </form>

        <br>

        <a href="/dashboard">
            Back to Dashboard
        </a>
        """

    shared_email = request.form.get(
        "shared_email",
        ""
    ).strip().lower()

    if not shared_email:

        return "Please enter email."

    # --------------------------------------------------------
    # CHECK FILE OWNER
    # --------------------------------------------------------

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE id=%s
        AND owner_email=%s
        """,
        (
            file_id,
            email
        )
    )

    file = cursor.fetchone()

    cursor.close()
    conn.close()

    if not file:

        return "File not found or access denied."

    filename = file["filename"]

    # ========================================================
    # INTERNAL / EXTERNAL SHARING
    # ========================================================

    if shared_email == email:

        sharing_type = "INTERNAL"

        risk_level = "LOW"

    else:

        sharing_type = "EXTERNAL"

        risk_level = "HIGH"

    # ========================================================
    # INSERT SHARING LOG
    # ========================================================

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO sharing_logs
        (
            file_id,
            owner_email,
            shared_email,
            sharing_type,
            risk_level
        )
        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """,
        (
            file_id,
            email,
            shared_email,
            sharing_type,
            risk_level
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    # ========================================================
    # ACTIVITY LOG
    # ========================================================

    log_activity(
        username,
        email,
        "FILE_SHARING",
        f"Shared {filename} with {shared_email}"
    )

    # ========================================================
    # USER BEHAVIOR ANALYTICS
    # ========================================================

    process_uba(
        username,
        email,
        "FILE_SHARING"
    )

    # ========================================================
    # SECURITY AUDIT
    # ========================================================

    log_security_event(
        session.get(
            "username",
            "Unknown"
        ),
        email,
        "FILE_SHARING",
        f"{filename} shared with {shared_email}",
        sharing_type,
        request.remote_addr
    )

    # ========================================================
    # EXTERNAL ALERT
    # ========================================================

    if sharing_type == "EXTERNAL":

        send_alert(
            email,
            filename,
            80
        )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# FILE INTEGRITY CHECK
# ============================================================

@app.route(
    "/check-integrity/<int:file_id>"
)
def check_integrity(file_id):

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    email = session.get("email")

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT *
        FROM files
        WHERE id=%s
        AND owner_email=%s
        """,
        (
            file_id,
            email
        )
    )

    file = cursor.fetchone()

    cursor.close()
    conn.close()

    if not file:

        return "File not found or access denied."

    filename = file["filename"]

    filepath = os.path.join(
        app.root_path,
        "uploads",
        filename
    )

    try:

        result = check_file_integrity(
            filepath,
            file["file_hash"]
        )

    except Exception as e:

        print(
            "Integrity error:",
            e
        )

        result = "INTEGRITY_CHECK_ERROR"

    # --------------------------------------------------------
    # ACTIVITY LOG
    # --------------------------------------------------------

    log_activity(
        session.get("username"),
        email,
        "FILE_INTEGRITY_CHECK",
        f"{filename}: {result}"
    )

    # --------------------------------------------------------
    # SECURITY AUDIT
    # --------------------------------------------------------

    log_security_event(
        session.get(
            "username",
            "Unknown"
        ),
        email,
        "FILE_INTEGRITY",
        f"{filename}: {result}",
        "CHECKED",
        request.remote_addr
    )

    return str(result)


# ============================================================
# SECURITY DASHBOARD
# ============================================================

@app.route("/security-dashboard")
def security_dashboard():

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    # --------------------------------------------------------
    # TOTAL USERS
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total_users
        FROM users
        """
    )

    total_users = cursor.fetchone()[
        "total_users"
    ]

    # --------------------------------------------------------
    # TOTAL FILES
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total_files
        FROM files
        """
    )

    total_files = cursor.fetchone()[
        "total_files"
    ]

    # --------------------------------------------------------
    # BLOCKED USERS
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT *
        FROM blocked_users
        ORDER BY blocked_at DESC
        """
    )

    blocked_users = cursor.fetchall()

    total_blocked = len(
        blocked_users
    )

    # --------------------------------------------------------
    # FAILED LOGIN COUNT
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS failed_logins
        FROM security_audit_logs
        WHERE activity_type='LOGIN'
        AND risk_level='FAILED'
        """
    )

    failed_logins = cursor.fetchone()[
        "failed_logins"
    ]

    # --------------------------------------------------------
    # HIGH RISK EVENTS
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS high_risk_events
        FROM security_audit_logs
        WHERE risk_level IN
        (
            'HIGH_RISK',
            'HIGH',
            'Critical'
        )
        """
    )

    high_risk_events = cursor.fetchone()[
        "high_risk_events"
    ]

    # --------------------------------------------------------
    # CRITICAL INCIDENTS
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS critical_incidents
        FROM security_audit_logs
        WHERE risk_level IN
        (
            'ACCOUNT_BLOCKED',
            'HIGH_RISK',
            'HIGH',
            'Critical'
        )
        """
    )

    critical_incidents = cursor.fetchone()[
        "critical_incidents"
    ]

    # --------------------------------------------------------
    # RECENT SECURITY EVENTS
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT *
        FROM security_audit_logs
        ORDER BY id DESC
        LIMIT 10
        """
    )

    recent_events = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "security_dashboard.html",
        total_users=total_users,
        total_files=total_files,
        blocked_users=blocked_users,
        total_blocked=total_blocked,
        failed_logins=failed_logins,
        high_risk_events=high_risk_events,
        critical_incidents=critical_incidents,
        recent_events=recent_events
    )


# ============================================================
# SECURITY AUDIT
# ============================================================

@app.route("/security-audit")
def security_audit():

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT *
        FROM security_audit_logs
        ORDER BY id DESC
        """
    )

    audit_logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "security_audit.html",
        audit_logs=audit_logs
    )


# ============================================================
# REPORT
# ============================================================

@app.route("/report")
def report():

    if not session.get("authenticated"):
        return redirect(url_for("login"))

    email = session.get("email")

    conn = get_db_connection()

    if conn is None:
        return "Database connection failed."

    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            f.id,
            f.filename,
            f.filepath,
            f.owner_email,
            f.file_size,
            f.file_type,
            f.risk_score,
            f.risk_level,
            f.risk_reasons,
            f.file_hash,
            f.created_at,
            fa.reason,
            fa.scan_time,
            a.alert_message,
            a.created_at AS alert_time
        FROM files f
        LEFT JOIN file_analysis fa
            ON f.filename = fa.filename
            AND f.owner_email = fa.owner_email
        LEFT JOIN alerts a
            ON f.filename = a.filename
            AND f.owner_email = a.owner_email
        WHERE f.owner_email = %s
        ORDER BY f.id DESC
        """,
        (email,)
    )

    reports = cursor.fetchall()

    cursor.execute(
        """
        SELECT *
        FROM security_audit_logs
        WHERE email = %s
        ORDER BY id DESC
        """,
        (email,)
    )

    audit_logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "report.html",
        reports=reports,
        audit_logs=audit_logs,
        username=session.get("username")
    )



# ============================================================
# UNBLOCK USER
# ============================================================

@app.route("/unblock/<email>")
def unblock(email):

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    email = email.strip().lower()

    admin_email = session.get(
        "email"
    )

    username = session.get(
        "username"
    )

    # --------------------------------------------------------
    # UNBLOCK
    # --------------------------------------------------------

    unblock_user(email)

    # --------------------------------------------------------
    # ACTIVITY LOG
    # --------------------------------------------------------

    log_activity(
        username,
        admin_email,
        "USER_UNBLOCKED",
        f"User unblocked: {email}"
    )

    # --------------------------------------------------------
    # SECURITY AUDIT
    # --------------------------------------------------------

    log_security_event(
        username,
        admin_email,
        "ACCOUNT_SECURITY",
        f"User unblocked: {email}",
        "USER_UNBLOCKED",
        request.remote_addr
    )

    return redirect(
        url_for("security_dashboard")
    )


# ============================================================
# ROUTES
# ============================================================

@app.route("/routes")
def routes():

    if not session.get("authenticated"):

        return redirect(
            url_for("login")
        )

    return """
    <h2>DataShadow Routes</h2>

    <ul>

        <li>/</li>

        <li>/login</li>

        <li>/dashboard</li>

        <li>/upload</li>

        <li>/security-dashboard</li>

        <li>/security-audit</li>

        <li>/report</li>

        <li>/download/&lt;file_id&gt;</li>

        <li>/share/&lt;file_id&gt;</li>

        <li>/check-integrity/&lt;file_id&gt;</li>

        <li>/logout</li>

    </ul>
    """


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    if session.get("authenticated"):

        username = session.get(
            "username"
        )

        email = session.get(
            "email"
        )

        # ----------------------------------------------------
        # ACTIVITY LOG
        # ----------------------------------------------------

        log_activity(
            username,
            email,
            "LOGOUT",
            "User logged out"
        )

        # ----------------------------------------------------
        # SECURITY AUDIT
        # ----------------------------------------------------

        log_security_event(
            session.get(
                "username",
                "Unknown"
            ),
            email,
            "LOGOUT",
            "User logged out successfully",
            "SUCCESS",
            request.remote_addr
        )

    session.clear()

    return redirect(
        url_for("login")
    )




# ============================================================
# SECURITY INCIDENT MANAGEMENT
# ============================================================

@app.route("/security-incidents")
def security_incidents():

    # User must be logged in
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # Get the email of the currently logged-in user
    logged_in_email = session.get("email")

    conn = get_db_connection()

    if conn is None:
        return "Database connection failed."

    cursor = conn.cursor(dictionary=True)

    # --------------------------------------------------------
    # GET ONLY INCIDENTS OF THE LOGGED-IN USER
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT
            id,
            incident_type,
            description,
            risk_level,
            username,
            email,
            status,
            created_at
        FROM security_incidents
        WHERE email = %s
        ORDER BY id DESC
        """,
        (logged_in_email,)
    )

    incidents = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "security_incidents.html",
        incidents=incidents,
        username=session.get("username"),
        email=logged_in_email
    )






# ============================================================
# CHAIN OF CUSTODY
# ============================================================

@app.route("/chain-of-custody")
def chain_of_custody():

    if not session.get("authenticated"):
        return redirect(url_for("login"))

    username = session.get("username")
    email = session.get("email")

    conn = get_db_connection()

    if conn is None:
        return "Database connection failed."

    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT
            id,
            evidence_id,
            action,
            username,
            description,
            created_at
        FROM chain_of_custody
        WHERE username = %s
        ORDER BY id DESC
        """,
        (username,)
    )

    custody_logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "chain_of_custody.html",
        custody_logs=custody_logs,
        username=username,
        email=email
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print(
        "======================================"
    )

    print(
        "      DATASHADOW SECURITY SYSTEM"
    )

    print(
        "======================================"
    )

    print(
        "Server starting..."
    )

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )