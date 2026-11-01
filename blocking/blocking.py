from database import get_db_connection


# ============================================================
# BLOCK USER
# ============================================================

def block_user(username, email, reason):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO blocked_users
        (
            username,
            email,
            reason,
            status
        )
        VALUES
        (
            %s,
            %s,
            %s,
            'BLOCKED'
        )
        """,
        (
            username,
            email,
            reason
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    print("User blocked successfully.")


# ============================================================
# CHECK WHETHER USER IS BLOCKED
# ============================================================

def is_user_blocked(email):

    conn = get_db_connection()

    cursor = conn.cursor(
        dictionary=True
    )

    cursor.execute(
        """
        SELECT *
        FROM blocked_users
        WHERE email=%s
        AND status='BLOCKED'
        """,
        (email,)
    )

    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        return True

    return False


# ============================================================
# UNBLOCK USER
# ============================================================

def unblock_user(email):

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE blocked_users
        SET status='UNBLOCKED'
        WHERE email=%s
        AND status='BLOCKED'
        """,
        (email,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    print("User unblocked successfully.")

    return True