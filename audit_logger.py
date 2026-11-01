from database import get_db_connection
from flask import request


def log_security_event(
    username,
    email,
    activity_type,
    description,
    risk_level,
    ip_address=None
):

    conn = None
    cursor = None

    try:

        # Get IP address automatically
        if ip_address is None:
            ip_address = request.remote_addr

        # Connect to database
        conn = get_db_connection()

        if conn is None:
            print("ERROR: Database connection failed.")
            return False

        cursor = conn.cursor()

        # Insert security audit record
        sql = """
        INSERT INTO security_audit_logs
        (
            username,
            email,
            activity_type,
            description,
            risk_level,
            ip_address
        )
        VALUES
        (
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
                username,
                email,
                activity_type,
                description,
                risk_level,
                ip_address
            )
        )

        conn.commit()

        print("====================================")
        print("SECURITY AUDIT LOG SAVED")
        print("Username:", username)
        print("Email:", email)
        print("Activity:", activity_type)
        print("Description:", description)
        print("Risk:", risk_level)
        print("IP:", ip_address)
        print("====================================")

        return True

    except Exception as e:

        print("====================================")
        print("SECURITY AUDIT ERROR")
        print(e)
        print("====================================")

        return False

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()