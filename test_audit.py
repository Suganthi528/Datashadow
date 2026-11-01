from audit_logger import log_security_event


result = log_security_event(
    "TestUser",
    "test@gmail.com",
    "TEST",
    "Testing security audit system",
    "LOW",
    "127.0.0.1"
)

print("Result:", result)