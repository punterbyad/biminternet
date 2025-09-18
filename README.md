# BIM INTERNET SERVICES

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)

BIM INTERNET SERVICES is a comprehensive platform for managing MikroTik routers with advanced features for ISPs and network administrators. It simplifies router management, monitoring, and user access control with an intuitive interface and powerful analytics.

---

## Features

- **Router Management:** Configure and manage multiple MikroTik routers remotely.  
- **Packages & Vouchers:** Create, manage, and track internet packages and vouchers.  
- **KYC (Know Your Customer):** Verify users before granting network access.  
- **Access Managers:** Manage users’ online sessions and access permissions.  
- **VPN Integration:** Secure network access with built-in VPN management.  
- **Analytics Dashboard:** Real-time monitoring and reporting for all routers and users.

---

## Screenshots

<!-- Add screenshots here -->
![Dashboard](screenshots/dashboard.png)
![Router Management](screenshots/router-management.png)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/punterbyad/biminternet.git
   cd biminternet
Create and activate a virtual environment:

2. Create and activate a virtual environment:
python -m venv env
source env/bin/activate  # Linux / macOS
env\Scripts\activate     # Windows
Install dependencies:

3. Install dependencies:
pip install -r requirements.txt
Configure your environment variables in a .env file (do not commit .env):

4 Configure your environment variables in a .env file (do not commit .env):
SECRET_KEY=your-secret-key
DATABASE_URL=your-database-url
Run migrations and start the development server:

5. Run migrations and start the development server:
python manage.py migrate
python manage.py runserver

6. Contributing
Contributions are welcome! Please open an issue or submit a pull request.


