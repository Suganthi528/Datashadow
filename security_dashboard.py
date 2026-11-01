# =========================================================
# MODULE 10
# SECURITY INTELLIGENCE DASHBOARD
# =========================================================

@app.route("/security-dashboard")
def security_dashboard():

    if "email" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # -------------------------------------------------
    # TOTAL USERS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total_users
        FROM users
        """
    )

    total_users = cursor.fetchone()["total_users"]

    # -------------------------------------------------
    # TOTAL FILES
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total_files
        FROM files
        """
    )

    total_files = cursor.fetchone()["total_files"]

    # -------------------------------------------------
    # BLOCKED USERS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS total_blocked
        FROM blocked_users
        WHERE status = 'BLOCKED'
        """
    )

    total_blocked = cursor.fetchone()["total_blocked"]

    # -------------------------------------------------
    # FAILED LOGIN ATTEMPTS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS failed_logins
        FROM security_audit_logs
        WHERE activity_type = 'FAILED_LOGIN'
        """
    )

    failed_logins = cursor.fetchone()["failed_logins"]

    # -------------------------------------------------
    # HIGH RISK EVENTS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS high_risk_events
        FROM security_audit_logs
        WHERE risk_level = 'HIGH'
        """
    )

    high_risk_events = cursor.fetchone()["high_risk_events"]

    # -------------------------------------------------
    # CRITICAL INCIDENTS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT COUNT(*) AS critical_incidents
        FROM security_audit_logs
        WHERE risk_level = 'CRITICAL'
        """
    )

    critical_incidents = cursor.fetchone()["critical_incidents"]

    # -------------------------------------------------
    # RECENT SECURITY EVENTS
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT
            id,
            username,
            email,
            activity_type,
            description,
            risk_level,
            ip_address,
            created_at

        FROM security_audit_logs

        ORDER BY created_at DESC

        LIMIT 20
        """
    )

    security_events = cursor.fetchall()

    # -------------------------------------------------
    # BLOCKED USERS LIST
    # -------------------------------------------------

    cursor.execute(
        """
        SELECT
            id,
            username,
            email,
            reason,
            status,
            blocked_at

        FROM blocked_users

        WHERE status = 'BLOCKED'

        ORDER BY blocked_at DESC
        """
    )

    blocked_users = cursor.fetchall()

    # -------------------------------------------------
    # CLOSE DATABASE
    # -------------------------------------------------

    cursor.close()
    conn.close()

    # -------------------------------------------------
    # SEND DATA TO HTML
    # -------------------------------------------------

    return render_template(
        "security_dashboard.html",

        username=session["username"],

        total_users=total_users,

        total_files=total_files,

        total_blocked=total_blocked,

        failed_logins=failed_logins,

        high_risk_events=high_risk_events,

        critical_incidents=critical_incidents,

        security_events=security_events,

        blocked_users=blocked_users
    )