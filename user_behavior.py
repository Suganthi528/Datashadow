from database import get_db_connection
from incident_manager import create_security_incident
from automated_response import automated_incident_response


def analyze_user_behavior(username, email, activity_type):

    conn = None
    cursor = None

    try:

        # =====================================================
        # DATABASE CONNECTION
        # =====================================================

        conn = get_db_connection()

        if conn is None:
            return {
                "activity_count": 0,
                "risk_level": "LOW",
                "insider_threat": False,
                "incident_created": False,
                "automated_response": False
            }

        cursor = conn.cursor(dictionary=True)

        # =====================================================
        # COUNT USER ACTIVITY
        # Last 10 minutes
        # =====================================================

        cursor.execute(
            """
            SELECT COUNT(*) AS activity_count
            FROM user_behavior_logs
            WHERE email = %s
            AND activity_type = %s
            AND created_at >= NOW() - INTERVAL 10 MINUTE
            """,
            (
                email,
                activity_type
            )
        )

        result = cursor.fetchone()

        activity_count = result["activity_count"] + 1

        # =====================================================
        # RISK ANALYSIS
        # =====================================================

        risk_level = "LOW"

        # -----------------------------------------------------
        # FAILED LOGIN
        # -----------------------------------------------------

        if activity_type == "FAILED_LOGIN":

            if activity_count >= 5:
                risk_level = "CRITICAL"

            elif activity_count >= 3:
                risk_level = "HIGH"

            else:
                risk_level = "MEDIUM"

        # -----------------------------------------------------
        # FILE DOWNLOAD
        # -----------------------------------------------------

        elif activity_type == "FILE_DOWNLOAD":

            if activity_count >= 10:
                risk_level = "HIGH"

            elif activity_count >= 5:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

        # -----------------------------------------------------
        # FILE UPLOAD
        # -----------------------------------------------------

        elif activity_type == "FILE_UPLOAD":

            if activity_count >= 10:
                risk_level = "HIGH"

            elif activity_count >= 5:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

        # -----------------------------------------------------
        # FILE SHARING
        # -----------------------------------------------------

        elif activity_type == "FILE_SHARING":

            if activity_count >= 5:
                risk_level = "HIGH"

            elif activity_count >= 3:
                risk_level = "MEDIUM"

            else:
                risk_level = "LOW"

        # -----------------------------------------------------
        # ACCOUNT BLOCKED
        # -----------------------------------------------------

        elif activity_type == "ACCOUNT_BLOCKED":

            risk_level = "CRITICAL"

        # -----------------------------------------------------
        # OTHER ACTIVITIES
        # -----------------------------------------------------

        else:

            risk_level = "LOW"

        # =====================================================
        # SAVE USER BEHAVIOR
        # =====================================================

        cursor.execute(
            """
            INSERT INTO user_behavior_logs
            (
                username,
                email,
                activity_type,
                activity_count,
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
                username,
                email,
                activity_type,
                activity_count,
                risk_level
            )
        )

        conn.commit()

        # =====================================================
        # MODULE 25
        # INSIDER THREAT DETECTION
        # =====================================================

        insider_threat = False
        incident_created = False
        automated_response = False

        if risk_level in ["HIGH", "CRITICAL"]:

            insider_threat = True

            # -------------------------------------------------
            # CREATE INCIDENT DESCRIPTION
            # -------------------------------------------------

            description = (
                f"Insider threat detected. "
                f"User {username} performed "
                f"{activity_count} {activity_type} activities "
                f"within 10 minutes."
            )

            # -------------------------------------------------
            # CREATE SECURITY INCIDENT
            # -------------------------------------------------

            incident_created = create_security_incident(
                incident_type="INSIDER_THREAT",
                description=description,
                risk_level=risk_level,
                username=username,
                email=email
            )

            # =================================================
            # MODULE 26
            # AUTOMATED INCIDENT RESPONSE
            # =================================================

            automated_response = automated_incident_response(
                incident_type="INSIDER_THREAT",
                description=description,
                risk_level=risk_level,
                username=username,
                email=email
            )

            # -------------------------------------------------
            # CONSOLE OUTPUT
            # -------------------------------------------------

            print("====================================")
            print("INSIDER THREAT DETECTED")
            print("Username:", username)
            print("Email:", email)
            print("Activity:", activity_type)
            print("Activity Count:", activity_count)
            print("Risk Level:", risk_level)
            print("Incident Created:", incident_created)
            print(
                "Automated Response:",
                automated_response
            )
            print("====================================")

        # =====================================================
        # NORMAL UBA OUTPUT
        # =====================================================

        print(
            "UBA:",
            username,
            activity_type,
            activity_count,
            risk_level
        )

        # =====================================================
        # RETURN RESULT
        # =====================================================

        return {
            "activity_count": activity_count,
            "risk_level": risk_level,
            "insider_threat": insider_threat,
            "incident_created": incident_created,
            "automated_response": automated_response
        }

    # =========================================================
    # ERROR HANDLING
    # =========================================================

    except Exception as e:

        print("User behavior error:", e)

        return {
            "activity_count": 0,
            "risk_level": "LOW",
            "insider_threat": False,
            "incident_created": False,
            "automated_response": False
        }

    # =========================================================
    # CLOSE DATABASE
    # =========================================================

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()