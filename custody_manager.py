from database import get_db_connection


def log_custody_action(evidence_id, action, username, description):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            print("Database connection failed.")
            return False

        cursor = conn.cursor()

        sql = """
        INSERT INTO chain_of_custody
        (
            evidence_id,
            action,
            username,
            description
        )
        VALUES
        (
            %s,
            %s,
            %s,
            %s
        )
        """

        cursor.execute(
            sql,
            (
                evidence_id,
                action,
                username,
                description
            )
        )

        conn.commit()

        print("====================================")
        print("CHAIN OF CUSTODY LOGGED")
        print("Evidence ID:", evidence_id)
        print("Action:", action)
        print("Username:", username)
        print("====================================")

        return True

    except Exception as e:
        print("Chain of custody error:", e)
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if conn is not None:
            conn.close()
