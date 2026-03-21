-- Secure Site Database Schema
-- Blue Team Training Environment

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    credits INT DEFAULT 100,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    two_factor_secret VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table (for IDOR vulnerability)
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    name VARCHAR(100),
    email VARCHAR(100),
    message TEXT,
    is_private BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Job applications (for file upload)
CREATE TABLE applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    position VARCHAR(100),
    resume_path VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Activity logs (for log injection)
CREATE TABLE activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME,
    ip_address VARCHAR(45),
    user_agent TEXT,
    action VARCHAR(100),
    details TEXT,
    request_uri VARCHAR(255)
);

-- Audit logs (Security Hardening)
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    analyst VARCHAR(50),
    ip_address VARCHAR(45),
    action VARCHAR(100),
    target VARCHAR(255),
    result ENUM('success','failure','blocked'),
    details TEXT,
    user_agent VARCHAR(500)
);

-- Rate Limits (Security Hardening)
CREATE TABLE rate_limits (
    ip_action_key VARCHAR(100) PRIMARY KEY,
    request_count INT DEFAULT 1,
    window_start DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Shop items (for logic flaw)
CREATE TABLE shop_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    price INT,
    image_url VARCHAR(255)
);

-- Seed Data

-- Argon2 hashed users
INSERT INTO users (username, password, email, role, credits) VALUES 
('admin', '$argon2id$v=19$m=65536,t=4,p=1$bExtYlg0bmNHODdjUDhxVw$HvwszdZWsU6RKKSzjgy4ulJln6CetqRKHow7lwgdd4E', 'admin@cybertech.com', 'admin', 1000),
('analyst', '$argon2id$v=19$m=65536,t=4,p=1$UWNmZmFFYzFsckpWU3NKbQ$Tz59ZHHOe+bzpT+HeUINIgMwTae+dHMHsIqIAhrjLBQ', 'analyst@cybertech.com', 'analyst', 500);

-- Messages
INSERT INTO messages (user_id, name, email, message, is_private) VALUES 
(1, 'System', 'admin@cybertech.com', 'Welcome to the new secure platform.', 1),
(NULL, 'John Doe', 'john@example.com', 'I cannot login to my account. Please help!', 0),
(NULL, 'Jane Smith', 'jane@example.com', 'Great service! Very satisfied with the security audit.', 0);

-- Shop items (flag costs 1 million credits - need logic flaw to afford)
INSERT INTO shop_items (name, description, price, image_url) VALUES
('Standard Support', 'Basic email support - 48hr response time', 50, 'assets/support_basic.png'),
('Premium Support', '24/7 Phone and email support', 500, 'assets/support_premium.png'),
('Enterprise Support', 'Dedicated account manager', 5000, 'assets/support_enterprise.png'),
('Enterprise Support', 'Dedicated account manager', 5000, 'assets/support_enterprise.png');
