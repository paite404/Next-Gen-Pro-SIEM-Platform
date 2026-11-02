# Next-Gen-Pro-SIEM-Platform
A Python-engineered SIEM platform built on the Flask framework for real-time network telemetry monitoring, automated log analysis, and defensive security orchestration.


# Next Gen Pro: Network Security Management and SIEM Platform

## Project Overview
**Next Gen Pro** is an open-source, centralized, web-based intelligence platform designed to monitor, analyze, and control network traffic and security events natively across **MikroTik RouterOS** environments. Built to eliminate the operational blind spots of fragmented single-router management tools (Winbox/WebFig), the system integrates automated log parsing, proactive threat detection, multi-router parallel polling architectures, defensive firewall rule synchronization, and full-stack network/port auditing. 

This platform serves as my final year capstone engineering project submitted to **ISBAT University, Uganda**, in partial fulfillment of the award of the degree of **Bachelor of Science in Networking and Cybersecurity**, achieving an academic validation score of **77% (8 Credit Units)**.

---

## 🛠️ Core Functional Modules

*   **Module I: Authentication and Session Management**  
    Secures administrative entry paths via cryptographic SHA-256 password verification, enforces 12-hour HTTP-only session tokens, and hosts a dedicated `login_history` audit pipeline tracking username, remote IP, host MAC addresses (resolved via local ARP sub-routines), timestamps, and user-agents.
*   **Module II: Router Connection & Parallel Polling**  
    Implements the native RouterOS API socket wire protocol (handling length-prefixed word encoding, MD5 challenge-response validation, and standard `!done`/`!re`/`!trap` reply flows over TCP port 8728). Spawns an optimized concurrent processing engine powered by a Python `ThreadPoolExecutor` (configured up to `max_workers=10`) to gather system performance counters, active DHCP leases, and live syslog logs in parallel every 2 seconds.
*   **Module III: Firewall & Access Control Management**  
    Provides one-click defensive orchestration interfaces to append/teardown filtering entries. Network blocks inject twin `drop` policies inside both the `forward` and `input` chains labeled with a `"Blocked by Next Gen Pro"` identifier code. Web resource restrictions manipulate live RouterOS static entries, rerouting targeted domains to a black-hole address (`0.0.0.0`).
*   **Module IV: Network & Port Scanning Subsystem**  
    Probes `/24` subnet spaces for active MikroTik nodes using multi-threaded TCP sockets targeting signature connection targets (Ports 8291, 8728, 8729, 80, 443, 22). Features an autonomous port auditor evaluating target structures (Ports 1–1024), mapping open states to specialized risk categories (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
*   **Module V: Rule-Based SIEM Engine**  
    Maintains active telemetry inspection thresholds. Built-in heuristics monitor real-time event sequences; detecting 5 or more authentication failures within a 60-second window from a matching source IP instantly triggers a `CRITICAL` severity network alert.
*   **Module VI: Activity Logging & Plain-English Timeline**  
    Employs an advanced translation engine (`_humanize_log()`) powered by localized regular expression (Regex) mapping arrays. Translates raw, complex RouterOS logs into clear, actionable, human-readable timeline feeds tracking active DHCP assignments, wireless links, state shifts, and configuration modifications.
*   **Module VII: Bandwidth Analysis & Top-Talker Detection**  
    Queries the central RouterOS firewall connection tables programmatically. Aggregates and sorts active data payloads to calculate real-time Rx/Tx transaction rates per active user, surfacing the top 20 network consumers to enable proactive bandwidth governance.

---

## 🏗️ Technical Architecture & Ecosystem Layout

The platform relies on a normalized, production-hardened Three-Tier architecture designed to protect performance integrity under load:

*   **Tier I (Presentation):** Single-page web application (SPA) engineered with vanilla ES6+ JavaScript, HTML5 canvas charts (`Chart.js` v4.4.1), and custom styling frameworks running an adaptive cybersecurity dark interface configuration.
*   **Tier II (Logic Processing):** Python 3 / Flask micro-framework executing dynamic concurrent multi-threaded data scraping loops, regex line parsing pipelines, and native socket communication layers wrapped in non-blocking timeout handlers (`safe_run()`).
*   **Tier III (Data Persistence):** SQLite 3 database instance (`netsecops.db`) running Write-Ahead Logging mode (`PRAGMA journal_mode=WAL`) with a `busy_timeout` configuration of `5000 ms` to safely handle multiple concurrent background log writes and client UI reads.

### Database Schema Matrix (`netsecops.db` - 13 Tables)
1.  `users`: Administrative credential store housing SHA-256 password hash blocks and access profiles.
2.  `routers`: Core ledger tracking tracked appliance endpoints, connection metrics, load scales, and active software versions.
3.  `devices`: Stores collected endpoint states (IP, MAC, lease times, vendor names resolved via OUI lists).
4.  `logs`: Structured repository containing processed data fragments from parallel ingestion cycles.
5.  `alerts`: Security tracking table holding SIEM-flagged anomalies, prioritization metrics, and resolution parameters.
6.  `firewall_rules`: Maintains localized operational mirror entries of active policies deployed by the application.
7.  `sessions`: Controls token lifecycles and expiration parameters.
8.  `scan_results`: Persistent log storage containing port-scanning service classifications and risk profiles.
9.  `bandwidth_history`: Aggregates historical interface transmission metrics to populate trend visualization graphs.
10. `interface_bandwidth`: High-frequency storage log capturing per-interface data scales every 2 seconds.
11. `blocked_ips`: Unique lookup relational list tracking restricted host IPs mapped against specific destination appliances.
12. `blocked_websites`: Relational storage index mapping domain names blocked through target DNS configurations.
13. `login_history`: Audit trail tracking administrative authentication attempts, clients, and active user-agents.

---

## 🚀 Installation & Deployment Instructions

### Prerequisites
*   Operating System: Linux Workstation / Server Environment (Kali, Ubuntu, RHEL)
*   Runtime Engine: Python 3.x with package manager (`pip`)
*   Hardware Constraints: Minimum 2 GB RAM availability | 1 GB Free Storage Allocation
*   Network Access: Clear routing path to target MikroTik RouterOS appliances via TCP Port 8728

### 1. Replicate Project Environment
```bash
git clone https://github.com
cd Next-Gen-Pro-SIEM-Platform
```

### 2. Configure Local Environment State
Create a secured environment configuration file named `.env` in the root folder path:
```text
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=SECURE_APP_SECRET_TOKEN_HEX_STRING_HERE
LOG_PATH=/var/log/auth.log
```

### 3. Initialize Python Dependencies
Ensure you execute your local installation wrapper to fetch core application libraries:
```bash
pip install Flask python-dotenv
```

### 4. Boot Up the Ingestion Dashboard
*Note: Because the application interacts natively with host netfilter layers (`iptables`) and binds to socket listeners, execution demands elevated administrative capabilities.*
```bash
sudo python app.py
```
Once initialized, the platform will open a local loop interface, listening securely on port 5000 (`http://localhost:5000`).

---

## ⚖️ License & Research Integrity Statement
This platform is published as an open-source security tool for educational, research, and infrastructure defense workflows. Developed under the sequential milestone execution parameters of the **Waterfall Development Model**, all system architecture charts, data flow structures (Context, Level 0, Level 1 DFDs), and relational schemas represent original engineering contributions aimed at democratizing enterprise-grade SIEM insights for small-to-medium network architectures.
