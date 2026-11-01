from database import get_db_connection


def create_security_incident(
    incident_type,
    description,
    risk_level,
    username,
    email
):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            print("Incident database connection failed.")
            return False

        cursor = conn.cursor()

        sql = """
        INSERT INTO security_incidents
        (
            incident_type,
            description,
            risk_level,
            username,
            email,
            status
        )
        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s,
            'DETECTED'
        )
        """

        cursor.execute(
            sql,
            (
                incident_type,
                description,
                risk_level,
                username,
                email
            )
        )

        conn.commit()

        print("====================================")
        print("SECURITY INCIDENT CREATED")
        print("Type:", incident_type)
        print("User:", username)
        print("Email:", email)
        print("Risk:", risk_level)
        print("====================================")

        return True

    except Exception as e:
        print("Incident creation error:", e)
        return False

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()