from database import get_db_connection

def log_activity(username, user_email, activity_type, description):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """
        INSERT INTO activity_logs
        (username, user_email, activity_type, description)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            sql,
            (
                username,
                user_email,
                activity_type,
                description
            )
        )

        conn.commit()
        print("Activity logged successfully.")

    except Exception as e:
        print("Activity logging error:", e)

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()