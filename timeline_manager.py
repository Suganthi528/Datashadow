from database import get_db_connection


def log_timeline_event(
    incident_id,
    event_type,
    description,
    username,
    email
):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            print("Timeline: Database connection failed.")
            return False

        cursor = conn.cursor()

        sql = """
        INSERT INTO incident_timeline
        (
            incident_id,
            event_type,
            description,
            username,
            email
        )
        VALUES
        (
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
                incident_id,
                event_type,
                description,
                username,
                email
            )
        )

        conn.commit()

        print("====================================")
        print("THREAT TIMELINE EVENT LOGGED")
        print("Event:", event_type)
        print("Username:", username)
        print("Description:", description)
        print("====================================")

        return True

    except Exception as e:
        print("Timeline logging error:", e)
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()