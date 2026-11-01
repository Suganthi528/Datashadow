USE datashadow;

CREATE TABLE activity_logs (

    id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(100),

    user_email VARCHAR(150),

    activity_type VARCHAR(50),

    description VARCHAR(255),

    filename VARCHAR(255),

    activity_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);