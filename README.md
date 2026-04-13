# CyberTech ThreatPulse - Blue Team Dashboard

This is a live, forensic-ready security operations center (SOC) dashboard designed for Blue Team training, threat intelligence ingestion, and log analysis.

## Features
- **ThreatPulse SIEM Dashboard (`dashboard.php`)**: An interactive, dynamic UI visualizing attacks via an integrated global geographic SVG map spanning top attackers and categories.
- **Real-Time Threat Intelligence API Integrations**: Streams active botnet C2s and live compromised IPs from Feodo Tracker, Emerging Threats, CINS Army, BlocklistDE, and ThreatFox (`api_fetch.php`, `feodo_realtime.php`).
- **Geolocation Integration**: Connects dynamically to IP-API to plot and rank attacks by country and coordinate in real-time.
- **Automated Ingestion**: Built-in PHP cron services and background fetchers mimicking a real enterprise SIEM data pipeline.
- **Investigative Terminal (`terminal.php`)**: A web-based simulated terminal for incident response actions.

## 🚀 Quick Start (Docker - Recommended)

1. Clone the repository and navigate to the project directory.
2. Build and start the services using Docker Compose:
   ```bash
   docker compose up -d --build
   ```
   *(Note: prefix with `sudo` if your user is not in the docker group).*
3. Open your browser and navigate to: `http://localhost:8080/`

## 🛠 Manual Setup (XAMPP / Apache / Nginx)

1. Copy all project files to your web root folder (e.g., `/var/www/html/` or `htdocs`).
2. Start **Apache** and **MySQL/MariaDB**.
3. Create a database named `cybertech_db`.
4. Import `database.sql` into the database.
5. In `includes/db.php` and script files, verify the local `$db_host` parses correctly to `localhost` or `127.0.0.1` depending on your environment.
6. Setup your local cronjobs for live ingestion:
   ```bash
   */5 * * * * php /path/to/project/feodo_realtime.php >> /var/log/feodo_realtime.log 2>&1
   */30 * * * * php /path/to/project/api_fetch.php >> /var/log/threat_fetch.log 2>&1
   ```
7. Access via your local web browser.

## 🛡️ Admin Access
- **Main Portal**: `/dashboard.php`
- **Username**: `admin`
- **Password**: `admin123` *(Seeded in the database)*
