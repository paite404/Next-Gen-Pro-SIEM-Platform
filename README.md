# Next-Gen-Pro-SIEM-Platform
A Python-engineered SIEM platform built on the Flask framework for real-time network telemetry monitoring, automated log analysis, and defensive security orchestration.


# Next Gen Pro: A Python-Engineered SIEM & Network Security Platform

## Project Overview
**Next Gen Pro** is a scalable, lightweight Security Information and Event Management (SIEM) engine engineered to ingest, parse, and correlate multi-source enterprise log telemetry in real-time. Built on a Python backend utilizing the Flask framework and optimized for deployment within Linux-administered architectures, the platform bridges the gap between raw syslog data streams and actionable defensive response. It features behavioral event correlation tracking, automated firewall control integration, and localized intrusion detection monitoring to aggressively minimize alert-mitigation latency.

This platform was developed as my final year capstone project for my Bachelor of Science in Networking and Cybersecurity at ISBAT University, achieving an academic validation score of 77% (8 Credit Units).

## Core Technical Features
*   **Real-Time Log Ingestion & Parsing:** Dynamic log tailing and streaming pipeline built to ingest multi-source host logs (`/var/log/auth.log`, syslog) and network appliance telemetry.
*   **Algorithmic Event Correlation:** Advanced rule-processing engine that monitors security event frequencies to isolate multi-stage threat signatures (e.g., brute-force attacks, unauthorized access anomalies) while filtering out false-positive noise.
*   **Automated Firewall Toggles:** Direct integration with Linux netfilter (`iptables`) utilizing secure subprocess calls to drop, block, or isolate malicious source IP addresses automatically upon alert trigger.
*   **Intuitive Security Dashboard:** Responsive front-end data visualization providing active threat levels, categorized log distribution statistics, and real-time security reporting metrics.

## Technical Architecture & Tech Stack
*   **Backend Framework:** Python / Flask
*   **Operating System Environment:** Linux Server (Ubuntu/RHEL Administration)
*   **Database & Storage Management:** SQLite / JSON-structured telemetry indices (`netsecops.db`)
*   **Network Protocols Leveraged:** Syslog (UDP 514), SSH, TCP/IP tracking
*   **Front-End Engine:** HTML5, CSS3, JavaScript data render arrays (`index.html`)

## Installation & Deployment Guide

### 1. Clone the Architecture
```bash
git clone https://github.com
cd Next-Gen-Pro-SIEM-Platform
```

### 2. Configure Environment Parameters
Create a `.env` file in the root directory to store secure parameters:
```text
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=your_secure_cryptographic_key_here
LOG_PATH=/var/log/auth.log
```

### 3. Initialize Dependency Modules
```bash
pip install Flask python-dotenv
```

### 4. Execute with System Privileges
*Note: Administrative/root privileges are required to allow the Python system engine to bind to sockets and modify local iptables configurations.*
```bash
sudo python app.py
```
The platform will initialize and become accessible via local loopback at `http://127.0.0.1:5000`.

## Security Engineering Values
*   **End-to-End Cryptographic Logging Integrity**
*   **Low-Latency Stream Data Synchronization**
*   **Highly Granular Operational Logging**
