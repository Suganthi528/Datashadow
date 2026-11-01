from audit_logger import log_security_event

log_security_event(
    "testuser",
    "test@gmail.com",
    "TEST_EVENT",
    "Module 9 audit logging test",
    "LOW",
    "127.0.0.1"
)