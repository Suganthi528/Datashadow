from database import get_db_connection
from blocking.blocking import block_user


def automated_incident_response(
    incident_type,
    description,
    risk_level,
    username,
    email
):

    conn = None
    cursor = None

    try:

        print("====================================")
        print("MODULE 26 - AUTOMATED RESPONSE")
        print("Incident:", incident_type)
        print("Username:", username)
        print("Email:", email)
        print("Risk:", risk_level)
        print("====================================")

        # =====================================================
        # CHECK RISK
        # =====================================================

        if risk_level not in ["HIGH", "CRITICAL"]:

            print("Risk is not HIGH/CRITICAL.")
            print("Automated response not required.")

            return False

        # =====================================================
        # CONNECT DATABASE
        # =====================================================

        conn = get_db_connection()

        if conn is None:

            print("ERROR: Database connection failed.")

            return False

        cursor = conn.cursor()

        print("Database connection successful.")

        # =====================================================
        # SAVE AUTOMATED RESPONSE FIRST
        # =====================================================

        action_taken = "USER ACCOUNT BLOCKED"

        sql = """
        INSERT INTO automated_response_logs
        (
            incident_type,
            username,
            email,
            risk_level,
            action_taken,
            description,
            response_status
        )
        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """

        cursor.execute(
            sql,
            (
                incident_type,
                username,
                email,
                risk_level,
                action_taken,
                description,
                "COMPLETED"
            )
        )

        conn.commit()

        print("====================================")
        print("AUTOMATED RESPONSE DATABASE SAVED")
        print("Incident:", incident_type)
        print("Risk:", risk_level)
        print("Action:", action_taken)
        print("Status: COMPLETED")
        print("====================================")

        # =====================================================
        # CLOSE RESPONSE DATABASE CONNECTION
        # =====================================================

        cursor.close()
        cursor = None

        conn.close()
        conn = None

        # =====================================================
        # AUTOMATIC USER BLOCK
        # =====================================================

        block_user(
            username,
            email,
            (
                f"Automated incident response: "
                f"{incident_type} - {risk_level}"
            )
        )

        print("====================================")
        print("AUTOMATED USER BLOCKING COMPLETED")
        print("Username:", username)
        print("Email:", email)
        print("====================================")

        return True

    except Exception as e:

        print("====================================")
        print("MODULE 26 ERROR")
        print(e)
        print("====================================")

        return False

    finally:

        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()