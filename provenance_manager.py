from database import get_db_connection


def log_provenance(
    file_id,
    filename,
    owner_email,
    source,
    action,
    username,
    description
):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()

        if conn is None:
            print("Provenance: Database connection failed.")
            return False

        cursor = conn.cursor()

        sql = """
        INSERT INTO file_provenance
        (
            file_id,
            filename,
            owner_email,
            source,
            action,
            description,
            username
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(
            sql,
            (
                file_id,
                filename,
                owner_email,
                source,
                action,
                description,
                username
            )
        )

        conn.commit()

        print("====================================")
        print("FILE PROVENANCE LOGGED")
        print("File ID:", file_id)
        print("Filename:", filename)
        print("Username:", username)
        print("Action:", action)
        print("Description:", description)
        print("====================================")

        return True

    except Exception as e:
        print("Provenance logging error:", e)
        return False

    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
