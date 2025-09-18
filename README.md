# BIM INTERNET SERVICES

[![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)

BIM INTERNET SERVICES is a comprehensive platform for managing MikroTik routers with advanced features for ISPs and network administrators. It simplifies router management, monitoring, and user access control with an intuitive interface and powerful analytics.

---

## Features

- **Router Management:** Configure and manage multiple MikroTik routers remotely.  
- **Packages & Vouchers:** Create, manage, and track internet packages and vouchers.  
- **KYC (Know Your Customer):** Verify users as needed by payment processors before disbursing large sums of money. 
- **Access Managers:** Manage users’ online sessions and access permissions.
- **Transactions:** Consolidate all your Collections, and withdraw your earnings at any time. 
- **VPN Integration:** Secure network access with built-in VPN management.  
- **Analytics Dashboard:** Real-time monitoring and reporting for all routers and users.

---

## Screenshots

<!-- Add screenshots here -->
![IMG-20250428-WA0000](https://github.com/user-attachments/assets/46694b6f-2aa9-4021-8a0f-031790d9d3ce)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/punterbyad/biminternet.git
   cd biminternet

2. Create and activate a virtual environment:
   ```bash
   python -m venv env
   source env/bin/activate  # Linux / macOS
   env\Scripts\activate     # Windows

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

4. Configure your environment variables in a .env file (do not commit .env):
   ```bash
   SECRET_KEY=your-secret-key
   DATABASE_URL=your-database-url
   
5. Run migrations and start the development server:
   ```bash
   python manage.py migrate
   python manage.py runserver

6. Contributing
   Contributions are welcome! Please open an issue or submit a pull request.


