# CyberTech Blue Team Training Environment

This is a secure, forensic-ready version of the CyberTech Solutions website, designed for Blue Team training and log analysis.

## Features
- **SIEM Dashboard**: Visualize attacks and analyze logs (`admin_siem.php`).
- **Forensic Logs**: Pre-loaded with `attacks.log` and `fulllogs.log` containing simulated attack signatures.
- **Investigative Terminal**: A web-based terminal (`terminal.php`) for simulating response actions.
- **Secure Codebase**: All previous CTF vulnerabilities (SQLi, XSS, etc.) have been patched.

## 🚀 Quick Start (Docker - Recommended)

If you have Docker Desktop installed:

1.  Double-click **`run_windows.bat`**
    *   This will build the environment and start the server.
2.  Open your browser to: `http://localhost:8000`

## 🛠 Manual Setup (XAMPP / Apache)

1.  Copy all files to your `htdocs` folder (e.g., `C:\xampp\htdocs\blueteam`).
2.  Start **Apache** and **MySQL** in XAMPP Control Panel.
3.  Create a database named `cybertech_db`.
4.  Import `database.sql` into the database (using PHPMyAdmin).
5.  Edit `includes/config.php` if your database password is not `root` or empty.
    ```php
    $db_user = "root";
    $db_pass = ""; // Default XAMPP password is usually empty
    ```
6.  Access via: `http://localhost/blueteam`

## 🛡️ Admin Access
- **URL**: `/login.php`
- **Username**: `analyst`
- **Password**: `kali` (Seeded in database.sql)

## 🔍 SIEM Dashboard
Login as Admin, then navigate to **Account -> Internal Dashboard** or **Admin Panel -> SIEM Dashboard**.
