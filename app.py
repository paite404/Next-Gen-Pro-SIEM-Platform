#!/usr/bin/env python3
"""
Next Gen Pro - Intelligent Network Security Management and SIEM Platform
for MikroTik Environments

Run: python app.py
Access: http://localhost:5000

THIS TOOL WAS BUILT BY GININGAKPIO STEPHEN PAITE JUSTIN
NETWORKING  &  CYBERSECURITY TECHNICIAN
https://github.com/paite404
"""

import os
import json
import time
import socket
import struct
import sqlite3
import hashlib
import secrets
import threading
import subprocess
import re
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed # <-- ADDED for parallel dashboard

from flask import (Flask, render_template, request, jsonify, session, g)

app = Flask(__name__, template_folder='.', static_folder='static')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_HTTPONLY'] = True


# DATABASE SETUP


DB_PATH = 'netsecops.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with get_db() as conn:
                conn.executescript('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'admin',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS routers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        mac TEXT,
                        name TEXT,
                        username TEXT,
                        password TEXT,
                        connection_type TEXT DEFAULT 'api',
                        status TEXT DEFAULT 'disconnected',
                        last_seen TIMESTAMP,
                        cpu_load INTEGER DEFAULT 0,
                        memory_used INTEGER DEFAULT 0,
                        uptime TEXT,
                        board_name TEXT,
                        version TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        ip TEXT,
                        mac TEXT,
                        hostname TEXT,
                        vendor TEXT,
                        interface TEXT,
                        connection_time TIMESTAMP,
                        last_seen TIMESTAMP,
                        is_suspicious INTEGER DEFAULT 0,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        level TEXT DEFAULT 'INFO',
                        category TEXT,
                        message TEXT,
                        source_ip TEXT,
                        raw_data TEXT,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        severity TEXT DEFAULT 'WARNING',
                        alert_type TEXT,
                        title TEXT,
                        description TEXT,
                        source_ip TEXT,
                        is_resolved INTEGER DEFAULT 0,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS firewall_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        chain TEXT DEFAULT 'forward',
                        action TEXT DEFAULT 'drop',
                        src_address TEXT,
                        dst_address TEXT,
                        protocol TEXT,
                        dst_port TEXT,
                        comment TEXT,
                        disabled INTEGER DEFAULT 0,
                        mikrotik_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        token TEXT UNIQUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_ip TEXT,
                        port INTEGER,
                        service TEXT,
                        state TEXT,
                        risk_level TEXT,
                        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS bandwidth_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        rx_bytes BIGINT DEFAULT 0,
                        tx_bytes BIGINT DEFAULT 0,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS interface_bandwidth (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        router_id INTEGER,
                        interface_name TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        rx_bps INTEGER DEFAULT 0,
                        tx_bps INTEGER DEFAULT 0,
                        rx_bytes_total BIGINT DEFAULT 0,
                        tx_bytes_total BIGINT DEFAULT 0,
                        FOREIGN KEY (router_id) REFERENCES routers(id)
                    );
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        router_id INTEGER,
                        reason TEXT,
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (router_id) REFERENCES routers(id),
                        UNIQUE(ip, router_id)
                    );
                    CREATE TABLE IF NOT EXISTS blocked_websites (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        website TEXT NOT NULL,
                        router_id INTEGER,
                        reason TEXT,
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (router_id) REFERENCES routers(id),
                        UNIQUE(website, router_id)
                    );
                    CREATE TABLE IF NOT EXISTS login_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        ip_address TEXT,
                        mac_address TEXT,
                        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'success',
                        user_agent TEXT
                    );
                ''')
                pwd_hash = hashlib.sha256('admin'.encode()).hexdigest()
                try:
                    conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                                 ('admin', pwd_hash, 'admin'))
                except sqlite3.IntegrityError:
                    pass
                conn.commit()
                return
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e) and attempt < max_retries - 1:
                print(f"Database locked, retrying... ({attempt+1}/{max_retries})")
                time.sleep(2)
                continue
            else:
                raise

init_db()


# MIKROTIK API CLIENT


class MikroTikAPI:
    def __init__(self, host, username='admin', password='', port=8728, timeout=6):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.connected = False
        self._lock = threading.Lock()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(self.timeout)
            self.connected = True
            return self._login()
        except Exception as e:
            self.connected = False
            raise ConnectionError(f"Failed to connect: {e}")

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.connected = False

    def _encode_length(self, length):
        if length < 0x80:
            return struct.pack('B', length)
        elif length < 0x4000:
            length |= 0x8000
            return struct.pack('>H', length)
        elif length < 0x200000:
            length |= 0xC00000
            return struct.pack('>I', length)[1:]
        elif length < 0x10000000:
            length |= 0xE0000000
            return struct.pack('>I', length)
        else:
            return b'\xF0' + struct.pack('>I', length)

    def _decode_length(self):
        b = self.sock.recv(1)
        if not b:
            raise ConnectionError("Connection closed")
        b = ord(b)
        if b < 0x80:
            return b
        elif b < 0xC0:
            b &= ~0x80
            b <<= 8
            b += ord(self.sock.recv(1))
            return b
        elif b < 0xE0:
            b &= ~0xC0
            b <<= 8
            b += ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            return b
        elif b < 0xF0:
            b &= ~0xE0
            b <<= 8
            b += ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            return b
        else:
            b = ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            b <<= 8
            b += ord(self.sock.recv(1))
            return b

    def _write_word(self, word):
        encoded = word.encode('utf-8')
        self.sock.send(self._encode_length(len(encoded)) + encoded)

    def _write_sentence(self, words):
        for word in words:
            self._write_word(word)
        self.sock.send(b'\x00')

    def _read_word(self):
        length = self._decode_length()
        if length == 0:
            return ''
        word = b''
        while len(word) < length:
            chunk = self.sock.recv(length - len(word))
            if not chunk:
                raise ConnectionError("Connection closed")
            word += chunk
        return word.decode('utf-8', errors='replace')

    def _read_sentence(self):
        words = []
        while True:
            word = self._read_word()
            if word == '':
                break
            words.append(word)
        return words

    def _login(self):
        self._write_sentence(['/login', '=name=' + self.username, '=password=' + self.password])
        response = self._read_sentence()
        if response and response[0] == '!done':
            return True
        if response and '=ret=' in str(response):
            challenge = ''
            for word in response:
                if word.startswith('=ret='):
                    challenge = word[5:]
            if challenge:
                md5 = hashlib.md5()
                md5.update(b'\x00')
                md5.update(self.password.encode('utf-8'))
                md5.update(bytes.fromhex(challenge))
                self._write_sentence(['/login', '=name=' + self.username,
                                       '=response=00' + md5.hexdigest()])
                response = self._read_sentence()
                if response and response[0] == '!done':
                    return True
        raise ConnectionError("Login failed")

    def talk(self, command, params=None, timeout=None):
        if not self.connected:
            raise ConnectionError("Not connected")
        with self._lock:
            if timeout and self.sock:
                self.sock.settimeout(timeout)
            try:
                words = [command]
                if params:
                    for key, value in params.items():
                        words.append(f'={key}={value}')
                self._write_sentence(words)
                results = []
                while True:
                    sentence = self._read_sentence()
                    if not sentence:
                        continue
                    reply_type = sentence[0]
                    if reply_type == '!done':
                        break
                    elif reply_type == '!trap':
                        error_msg = ''
                        for word in sentence[1:]:
                            if word.startswith('=message='):
                                error_msg = word[9:]
                        raise Exception(f"RouterOS error: {error_msg}")
                    elif reply_type == '!re':
                        item = {}
                        for word in sentence[1:]:
                            if '=' in word[1:]:
                                key, value = word[1:].split('=', 1)
                                item[key] = value
                        results.append(item)
                return results
            finally:
                if timeout and self.sock:
                    self.sock.settimeout(self.timeout)

    def safe_run(self, command, params=None, timeout=4, default=None):
        """Run command with timeout, return default on any error (no exception)."""
        try:
            return self.talk(command, params, timeout=timeout)
        except Exception:
            return default if default is not None else []

    def get_identity(self):
        return self.talk('/system/identity/print', timeout=4)

    def get_resources(self):
        return self.talk('/system/resource/print', timeout=4)

    def get_interfaces(self):
        return self.talk('/interface/print', timeout=5)

    def get_dhcp_leases(self):
        return self.talk('/ip/dhcp-server/lease/print', timeout=5)

    def get_arp_table(self):
        return self.talk('/ip/arp/print', timeout=4)

    def get_logs(self):
        return self.talk('/log/print', timeout=5)

    def get_firewall_rules(self, chain='filter'):
        return self.talk(f'/ip/firewall/{chain}/print', timeout=5)

    def add_firewall_rule(self, chain='filter', **params):
        params.pop('chain', None)
        return self.talk(f'/ip/firewall/{chain}/add', params, timeout=5)

    def remove_firewall_rule(self, chain='filter', rule_id=''):
        return self.talk(f'/ip/firewall/{chain}/remove', {'.id': rule_id}, timeout=5)

    def run_command(self, command, params=None):
        return self.talk(command, params)


# ROUTER CONNECTIONS MANAGER

router_connections = {}

def get_router_api(router_id, auto_reconnect=True):
    """Return live API for router_id. If disconnected, attempt one silent reconnect."""
    if router_id in router_connections:
        api = router_connections[router_id]
        if api.connected:
            return api
        if auto_reconnect:
            try:
                with get_db() as conn:
                    r = conn.execute("SELECT * FROM routers WHERE id=?", (router_id,)).fetchone()
                if r and r['username'] and r['password'] is not None:
                    new_api = MikroTikAPI(r['ip'], r['username'], r['password'])
                    new_api.connect()
                    router_connections[router_id] = new_api
                    threading.Thread(target=monitor_router, args=(router_id,), daemon=True).start()
                    return new_api
            except Exception:
                pass
    return None


# NETWORK SCANNER


def get_default_gateway():
    try:
        with open('/proc/net/route') as f:
            for line in f:
                parts = line.strip().split()
                if parts[1] == '00000000':
                    gateway_hex = parts[2]
                    gateway_ip = socket.inet_ntoa(struct.pack('<I', int(gateway_hex, 16)))
                    return gateway_ip
    except:
        pass
    return None

def get_local_network():
    gateway = get_default_gateway()
    if gateway:
        parts = gateway.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    except:
        return "192.168.1"

# MikroTik Organizationally Unique Identifiers

MIKROTIK_OUI_PREFIXES = [
    'E4:8D:8C', '4C:5E:0C', '6C:3B:6B', 'D4:CA:6D', '2C:C8:1B',
    'B8:69:F4', '00:0C:42', 'CC:2D:E0', '48:A9:8A', '74:4D:28',
    '08:55:31', 'DC:2C:6E', '64:D1:54', '18:FD:74', 'C4:AD:34',
]

MIKROTIK_PORTS = [8291, 8728, 8729, 80, 443, 22]

def is_mikrotik_mac(mac):
    mac_upper = mac.upper().replace('-', ':')
    for prefix in MIKROTIK_OUI_PREFIXES:
        if mac_upper.startswith(prefix):
            return True
    return False

def scan_port(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

def scan_host(ip):
    result = {'ip': ip, 'is_mikrotik': False, 'mac': '', 'open_ports': [], 'name': ''}
    alive = False
    for port in [8291, 8728, 80, 22]:
        if scan_port(ip, port, 0.5):
            alive = True
            result['open_ports'].append(port)
            break
    if not alive:
        return None
    for port in MIKROTIK_PORTS:
        if port not in result['open_ports'] and scan_port(ip, port, 0.5):
            result['open_ports'].append(port)
    if 8291 in result['open_ports'] or 8728 in result['open_ports']:
        result['is_mikrotik'] = True
        result['name'] = 'MikroTik Router'
    try:
        if os.name == 'nt':
            output = subprocess.check_output(['arp', '-a', ip], timeout=5).decode()
        else:
            output = subprocess.check_output(['arp', '-n', ip], timeout=5).decode()
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', output)
        if mac_match:
            result['mac'] = mac_match.group(0).upper()
            if is_mikrotik_mac(result['mac']):
                result['is_mikrotik'] = True
    except:
        pass
    return result

def scan_network(subnet=None):
    if subnet is None:
        subnet = get_local_network()
    results = []
    threads = []
    results_lock = threading.Lock()
    def worker(ip):
        r = scan_host(ip)
        if r and r['is_mikrotik']:
            with results_lock:
                results.append(r)
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(target=worker, args=(ip,))
        threads.append(t)
        t.start()
        if len(threads) >= 50:
            for t in threads:
                t.join(timeout=3)
            threads = []
    for t in threads:
        t.join(timeout=3)
    return results

def port_scan(target_ip, port_range="1-1024"):
    results = []
    common_services = {
        21: ('FTP', 'HIGH'), 22: ('SSH', 'MEDIUM'), 23: ('Telnet', 'CRITICAL'),
        25: ('SMTP', 'MEDIUM'), 53: ('DNS', 'LOW'), 80: ('HTTP', 'LOW'),
        110: ('POP3', 'MEDIUM'), 143: ('IMAP', 'MEDIUM'), 443: ('HTTPS', 'LOW'),
        445: ('SMB', 'HIGH'), 993: ('IMAPS', 'LOW'), 995: ('POP3S', 'LOW'),
        1433: ('MSSQL', 'HIGH'), 1723: ('PPTP', 'HIGH'), 3306: ('MySQL', 'HIGH'),
        3389: ('RDP', 'HIGH'), 5432: ('PostgreSQL', 'HIGH'), 5900: ('VNC', 'HIGH'),
        8080: ('HTTP-Alt', 'MEDIUM'), 8291: ('WinBox', 'MEDIUM'),
        8728: ('MikroTik-API', 'MEDIUM'), 8729: ('MikroTik-API-SSL', 'LOW'),
    }
    start, end = map(int, port_range.split('-'))
    end = min(end, 65535)
    for port in range(start, end + 1):
        if scan_port(target_ip, port, 0.3):
            service, risk = common_services.get(port, ('Unknown', 'MEDIUM'))
            results.append({'port': port, 'service': service, 'state': 'open', 'risk_level': risk})
            with get_db() as conn:
                conn.execute("INSERT INTO scan_results (target_ip, port, service, state, risk_level) VALUES (?,?,?,?,?)",
                             (target_ip, port, service, 'open', risk))
                conn.commit()
    return results


# SIEM ENGINE — Brute Force Detection Only


class SIEMEngine:
    def __init__(self):
        self.rules = [
            {'name': 'Brute Force Detection', 'type': 'brute_force',
             'threshold': 5, 'window': 60, 'severity': 'CRITICAL'},
        ]
        self.event_buffer = defaultdict(list)

    def analyze_log(self, log_entry, router_id):
        message = log_entry.get('message', '').lower()
        timestamp = datetime.now()

        # Log successful and failed login events
        if 'login' in message and ('success' in message or 'failure' in message):
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
            src_ip = ip_match.group(1) if ip_match else 'unknown'
            user_match = re.search(r'user[=:\s]+(\w+)', message)
            username = user_match.group(1) if user_match else 'unknown'
            if 'success' in message:
                self._create_log(router_id, 'INFO', 'Login',
                                 f"Successful login by {username} from {src_ip}", src_ip)
            else:
                self._create_log(router_id, 'WARNING', 'Login',
                                 f"Failed login attempt by {username} from {src_ip}", src_ip)

        # Brute force detection: 5+ failed logins within 60 seconds from same IP
        if 'login failure' in message or 'authentication failed' in message:
            src_ip = self._extract_ip(message)
            self.event_buffer[f'brute_{src_ip}'].append(timestamp)
            self._check_threshold('brute_force', f'brute_{src_ip}', router_id, src_ip,
                                   f"Multiple failed login attempts from {src_ip}")

    def _extract_ip(self, message):
        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
        return match.group(1) if match else 'unknown'

    def _check_threshold(self, rule_type, buffer_key, router_id, src_ip, description):
        for rule in self.rules:
            if rule['type'] == rule_type:
                cutoff = datetime.now() - timedelta(seconds=rule['window'])
                self.event_buffer[buffer_key] = [t for t in self.event_buffer[buffer_key] if t > cutoff]
                if len(self.event_buffer[buffer_key]) >= rule['threshold']:
                    self._create_alert(router_id, rule['severity'], rule_type,
                                       rule['name'], description, src_ip)
                    self.event_buffer[buffer_key] = []
                break

    def _create_alert(self, router_id, severity, alert_type, title, description, src_ip):
        with get_db() as conn:
            conn.execute("""INSERT INTO alerts (router_id, severity, alert_type, title, description, source_ip)
                           VALUES (?,?,?,?,?,?)""", (router_id, severity, alert_type, title, description, src_ip))
            conn.commit()

    def _create_log(self, router_id, level, category, message, source_ip):
        with get_db() as conn:
            conn.execute("INSERT INTO logs (router_id, level, category, message, source_ip) VALUES (?,?,?,?,?)",
                         (router_id, level, category, message, source_ip))
            conn.commit()


siem = SIEMEngine()


# BACKGROUND MONITOR (Enhanced with per-interface bandwidth collection, polling every 1 second)


def monitor_router(router_id):
    while router_id in router_connections:
        api = router_connections.get(router_id)
        if not api or not api.connected:
            break
        try:
            resources = api.safe_run('/system/resource/print', timeout=4)
            if resources:
                res = resources[0]
                with get_db() as conn:
                    conn.execute("""UPDATE routers SET cpu_load=?, memory_used=?, uptime=?,
                                  board_name=?, version=?, status='connected', last_seen=?
                                  WHERE id=?""",
                                (res.get('cpu-load', 0),
                                 _calc_memory_pct(res.get('total-memory', '0'), res.get('free-memory', '0')),
                                 res.get('uptime', ''), res.get('board-name', ''),
                                 res.get('version', ''), datetime.now().isoformat(), router_id))
                    conn.commit()

            # Collect per-interface bandwidth - safe, non-blocking
            interfaces = api.safe_run('/interface/print', timeout=4) or []
            for iface in interfaces:
                iface_name = iface.get('name', '')
                if not iface_name:
                    continue
                rx_bytes = int(iface.get('rx-byte', 0))
                tx_bytes = int(iface.get('tx-byte', 0))
                rx_rate = int(iface.get('rx-rate', 0))
                tx_rate = int(iface.get('tx-rate', 0))
                try:
                    with get_db() as conn:
                        conn.execute("""INSERT INTO interface_bandwidth
                                       (router_id, interface_name, rx_bps, tx_bps, rx_bytes_total, tx_bytes_total)
                                       VALUES (?,?,?,?,?,?)""",
                                    (router_id, iface_name, rx_rate, tx_rate, rx_bytes, tx_bytes))
                        conn.commit()
                except Exception:
                    pass
            if interfaces:
                total_rx = sum(int(i.get('rx-byte', 0)) for i in interfaces)
                total_tx = sum(int(i.get('tx-byte', 0)) for i in interfaces)
                try:
                    with get_db() as conn:
                        conn.execute("INSERT INTO bandwidth_history (router_id, rx_bytes, tx_bytes) VALUES (?,?,?)",
                                    (router_id, total_rx, total_tx))
                        conn.commit()
                except Exception:
                    pass


            # Process logs with SIEM - safe, non-blocking
            logs = api.safe_run('/log/print', timeout=4) or []
            for log in logs[-20:]:
                msg = log.get('message', '')
                level = 'INFO'
                if 'error' in msg.lower() or 'critical' in msg.lower():
                    level = 'CRITICAL'
                elif 'warning' in msg.lower():
                    level = 'WARNING'
                try:
                    siem.analyze_log({'message': msg, 'level': level}, router_id)
                except Exception:
                    pass

        except Exception as e:
            print(f"Monitor error for router {router_id}: {e}")
            break
        time.sleep(2)  # 2-second polling — fast enough, easy on CPU

def _calc_memory_pct(total, free):
    try:
        t = int(total)
        f = int(free)
        if t > 0:
            return int(((t - f) / t) * 100)
    except:
        pass
    return 0


# AUTH DECORATOR


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ROUTES


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    key = session.get('_id')
    if key and key in active_sessions:
        del active_sessions[key]
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/status')
def auth_status():
    if 'user_id' in session:
        return jsonify({'authenticated': True, 'username': session['username']})
    return jsonify({'authenticated': False})

# active sessions tracker
active_sessions = {}

@app.before_request
def track_session():
    if 'user_id' in session:
        key = session.get('_id', id(session))
        active_sessions[key] = {
            'username': session.get('username', 'Unknown'),
            'login_time': session.get('login_time', datetime.now().isoformat()),
            'ip': request.remote_addr,
            'user_id': session['user_id'],
        }

def get_mac_from_ip(ip):
    """Try to resolve MAC address from ARP table for a given IP."""
    try:
        if os.name == 'nt':
            output = subprocess.check_output(['arp', '-a', ip], timeout=3).decode()
        else:
            output = subprocess.check_output(['arp', '-n', ip], timeout=3).decode()
        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', output)
        if mac_match:
            return mac_match.group(0).upper()
    except:
        pass
    return 'N/A'

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    mac = get_mac_from_ip(client_ip)
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? AND password_hash=?",
                            (username, pwd_hash)).fetchone()
    if user:
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['login_time'] = datetime.now().isoformat()
        import random; session['_id'] = random.randint(100000,999999)
        active_sessions[session['_id']] = {
            'username': user['username'],
            'login_time': session['login_time'],
            'ip': client_ip,
            'user_id': user['id'],
        }
        with get_db() as conn:
            conn.execute("INSERT INTO login_history (username, ip_address, mac_address, status, user_agent) VALUES (?,?,?,?,?)",
                         (username, client_ip, mac, 'success', user_agent))
            conn.commit()
        return jsonify({'success': True, 'username': user['username']})
    # Record failed attempt
    with get_db() as conn:
        conn.execute("INSERT INTO login_history (username, ip_address, mac_address, status, user_agent) VALUES (?,?,?,?,?)",
                     (username, client_ip, mac, 'failed', user_agent))
        conn.commit()
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/active-users')
@login_required
def active_users():
    users = list(active_sessions.values())
    return jsonify({'users': users, 'count': len(users)})

@app.route('/api/login-history')
@login_required
def login_history_api():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM login_history ORDER BY login_time DESC LIMIT 500").fetchall()
    return jsonify({'history': [dict(r) for r in rows]})

# Change password
@app.route('/api/user/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    if not new_password:
        return jsonify({'error': 'New password required'}), 400
    user_id = session['user_id']
    old_hash = hashlib.sha256(old_password.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
        if not user or user['password_hash'] != old_hash:
            return jsonify({'error': 'Invalid current password'}), 401
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
        conn.commit()
    return jsonify({'success': True})

# Change username
@app.route('/api/user/change-username', methods=['POST'])
@login_required
def change_username():
    data = request.json
    new_username = data.get('new_username', '').strip()
    password = data.get('password', '')
    if not new_username or len(new_username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    user_id = session['user_id']
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=? AND password_hash=?", (user_id, pwd_hash)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid password'}), 401
        existing = conn.execute("SELECT id FROM users WHERE username=? AND id!=?", (new_username, user_id)).fetchone()
        if existing:
            return jsonify({'error': 'Username already taken'}), 400
        conn.execute("UPDATE users SET username=? WHERE id=?", (new_username, user_id))
        conn.commit()
    session['username'] = new_username
    key = session.get('_id')
    if key and key in active_sessions:
        active_sessions[key]['username'] = new_username
    return jsonify({'success': True, 'username': new_username})

# Clear history endpoints
@app.route('/api/history/logs', methods=['DELETE'])
@login_required
def clear_log_history():
    with get_db() as conn:
        conn.execute("DELETE FROM logs")
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/history/alerts', methods=['DELETE'])
@login_required
def clear_alert_history():
    with get_db() as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/history/all', methods=['DELETE'])
@login_required
def clear_all_history():
    with get_db() as conn:
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM bandwidth_history")
        conn.execute("DELETE FROM interface_bandwidth")
        conn.execute("DELETE FROM scan_results")
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/history/login', methods=['DELETE'])
@login_required
def clear_login_history():
    with get_db() as conn:
        conn.execute("DELETE FROM login_history")
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/history/router/<int:router_id>', methods=['DELETE'])
@login_required
def delete_router_history(router_id):
    with get_db() as conn:
        conn.execute("DELETE FROM routers WHERE id=? AND status='disconnected'", (router_id,))
        conn.commit()
    return jsonify({'success': True})

# SIEM stats for charts
@app.route('/api/siem/stats')
@login_required
def siem_stats():
    with get_db() as conn:
        total_logs = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()['c']
        critical = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='CRITICAL'").fetchone()['c']
        warning = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='WARNING'").fetchone()['c']
        info_count = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE severity='INFO'").fetchone()['c']
        unresolved = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE is_resolved=0").fetchone()['c']
        by_type = conn.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC LIMIT 10").fetchall()
        recent_24h = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE timestamp > datetime('now', '-24 hours')").fetchone()['c']
        by_hour = conn.execute("""SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt 
                                   FROM alerts WHERE timestamp > datetime('now', '-24 hours') 
                                   GROUP BY hour ORDER BY hour""").fetchall()
        log_levels = conn.execute("SELECT level, COUNT(*) as cnt FROM logs GROUP BY level").fetchall()
        top_ips = conn.execute("SELECT source_ip, COUNT(*) as cnt FROM alerts WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 10").fetchall()
    return jsonify({
        'total_logs': total_logs, 'critical': critical, 'warning': warning,
        'info': info_count, 'unresolved': unresolved,
        'by_type': [dict(r) for r in by_type],
        'recent_24h': recent_24h,
        'by_hour': [dict(r) for r in by_hour],
        'log_levels': [dict(r) for r in log_levels],
        'top_ips': [dict(r) for r in top_ips],
    })

# Network scanning
@app.route('/api/scan/network', methods=['POST'])
@login_required
def api_scan_network():
    data = request.json
    subnet = data.get('subnet', None)
    results = scan_network(subnet)
    return jsonify({'routers': results, 'local_network': get_local_network()})

@app.route('/api/scan/ports', methods=['POST'])
@login_required
def api_scan_ports():
    data = request.json
    target = data.get('target', '')
    port_range = data.get('range', '1-1024')
    if not target:
        return jsonify({'error': 'Target IP required'}), 400
    results = port_scan(target, port_range)
    return jsonify({'results': results, 'target': target})

# Router management
@app.route('/api/router/connect', methods=['POST'])
@login_required
def connect_router():
    data = request.json
    ip = data.get('ip', '')
    username = data.get('username', 'admin')
    password = data.get('password', '')
    port = int(data.get('port', 8728))
    try:
        api = MikroTikAPI(ip, username, password, port)
        api.connect()
        identity = api.get_identity()
        resources = api.get_resources()
        router_name = identity[0].get('name', 'MikroTik') if identity else 'MikroTik'
        with get_db() as conn:
            cursor = conn.execute("""INSERT INTO routers (ip, name, username, password, status, last_seen,
                                    board_name, version) VALUES (?,?,?,?,?,?,?,?)""",
                                  (ip, router_name, username, password, 'connected',
                                   datetime.now().isoformat(),
                                   resources[0].get('board-name', '') if resources else '',
                                   resources[0].get('version', '') if resources else ''))
            router_id = cursor.lastrowid
            conn.commit()
        router_connections[router_id] = api
        threading.Thread(target=monitor_router, args=(router_id,), daemon=True).start()
        return jsonify({
            'success': True, 'router_id': router_id, 'name': router_name,
            'board': resources[0].get('board-name', '') if resources else '',
            'version': resources[0].get('version', '') if resources else ''
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/router/<int:router_id>/disconnect', methods=['POST'])
@login_required
def disconnect_router(router_id):
    if router_id in router_connections:
        router_connections[router_id].disconnect()
        del router_connections[router_id]
    with get_db() as conn:
        conn.execute("UPDATE routers SET status='disconnected' WHERE id=?", (router_id,))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/router/<int:router_id>/status')
@login_required
def router_status(router_id):
    with get_db() as conn:
        router = conn.execute("SELECT * FROM routers WHERE id=?", (router_id,)).fetchone()
    if router:
        return jsonify(dict(router))
    return jsonify({'error': 'Router not found'}), 404

@app.route('/api/router/<int:router_id>/resources')
@login_required
def router_resources(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        resources = api.get_resources()
        return jsonify({'resources': resources})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/interfaces')
@login_required
def router_interfaces(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        return jsonify({'interfaces': api.get_interfaces()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/devices')
@login_required
def router_devices(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        leases = api.get_dhcp_leases()
        devices = []
        for lease in leases:
            device = {
                'ip': lease.get('address', ''),
                'mac': lease.get('mac-address', ''),
                'hostname': lease.get('host-name', 'Unknown'),
                'status': lease.get('status', ''),
                'last_seen': lease.get('last-seen', ''),
                'server': lease.get('server', ''),
            }
            if is_mikrotik_mac(device['mac']):
                device['vendor'] = 'MikroTik'
            devices.append(device)
        with get_db() as conn:
            for d in devices:
                conn.execute("""INSERT OR REPLACE INTO devices (router_id, ip, mac, hostname, vendor, last_seen)
                              VALUES (?,?,?,?,?,?)""",
                            (router_id, d['ip'], d['mac'], d['hostname'], d.get('vendor', ''),
                             datetime.now().isoformat()))
            conn.commit()
        return jsonify({'devices': devices})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/wifi-clients')
@login_required
def get_wifi_clients(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    clients = []
    hotspot_clients = []
    # Use safe_run with short timeouts so slow/missing features don't block
    wl = api.safe_run('/interface/wireless/registration-table/print', timeout=4)
    for c in (wl or []):
        c['_type'] = 'wifi'
        clients.append(c)
    cap = api.safe_run('/caps-man/registration-table/print', timeout=3)
    for c in (cap or []):
        c['_type'] = 'capsman'
        clients.append(c)
    hs = api.safe_run('/ip/hotspot/active/print', timeout=4)
    for c in (hs or []):
        c['_type'] = 'hotspot'
        hotspot_clients.append(c)
    return jsonify({'clients': clients, 'hotspot': hotspot_clients})

# Firewall
@app.route('/api/router/<int:router_id>/firewall')
@login_required
def get_firewall(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    rules = api.safe_run('/ip/firewall/filter/print', timeout=5) or []
    nat = api.safe_run('/ip/firewall/nat/print', timeout=5) or []
    return jsonify({'filter': rules, 'nat': nat})

@app.route('/api/router/<int:router_id>/firewall/add', methods=['POST'])
@login_required
def add_firewall(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    try:
        params = {}
        for k in ('chain', 'action', 'src-address', 'dst-address', 'protocol', 'dst-port', 'comment'):
            if data.get(k):
                params[k] = data[k]
        result = api.talk('/ip/firewall/filter/add', params)
        with get_db() as conn:
            conn.execute("""INSERT INTO firewall_rules (router_id, chain, action, src_address, dst_address,
                           protocol, dst_port, comment) VALUES (?,?,?,?,?,?,?,?)""",
                        (router_id, data.get('chain','forward'), data.get('action','drop'),
                         data.get('src-address',''), data.get('dst-address',''),
                         data.get('protocol',''), data.get('dst-port',''), data.get('comment','')))
            conn.commit()
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/firewall/remove', methods=['POST'])
@login_required
def remove_firewall(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    try:
        result = api.remove_firewall_rule('filter', data.get('id', ''))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# IP and Website blocking (FIXED DOMAIN BLOCKING)
@app.route('/api/router/<int:router_id>/block-ip', methods=['POST'])
@login_required
def block_ip(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    ip_to_block = data.get('ip', '')
    if not ip_to_block:
        return jsonify({'error': 'IP required'}), 400
    try:
        ts = datetime.now().isoformat()
        api.talk('/ip/firewall/filter/add', {
            'chain': 'forward', 'action': 'drop',
            'src-address': ip_to_block,
            'comment': f'Blocked by Next Gen Pro - {ip_to_block} - {ts}'
        })
        api.talk('/ip/firewall/filter/add', {
            'chain': 'input', 'action': 'drop',
            'src-address': ip_to_block,
            'comment': f'Blocked by Next Gen Pro - {ip_to_block} - {ts}'
        })
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO blocked_ips (ip, router_id, reason) VALUES (?,?,?)",
                         (ip_to_block, router_id, f'Blocked via Next Gen Pro at {datetime.now()}'))
            conn.commit()
        return jsonify({'success': True, 'message': f'IP {ip_to_block} blocked'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/block-website', methods=['POST'])
@login_required
def block_website(router_id):
    """Block a website using DNS static entry (MikroTik native method)"""
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    website = data.get('website', '').strip()
    if not website:
        return jsonify({'error': 'Website required'}), 400

    # Clean domain: remove protocol and path
    website = website.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]
    try:
        # Add DNS static entry pointing to 0.0.0.0 (blackhole)
        api.run_command('/ip/dns/static/add', {
            'name': website,
            'address': '0.0.0.0',
            'comment': f'Blocked by Next Gen Pro - {website}'
        })
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO blocked_websites (website, router_id, reason) VALUES (?,?,?)",
                         (website, router_id, f'Blocked via DNS static entry at {datetime.now()}'))
            conn.commit()
        return jsonify({'success': True, 'message': f'Website {website} blocked via DNS'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocked/ips')
@login_required
def list_blocked_ips():
    with get_db() as conn:
        blocked = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    return jsonify({'blocked': [dict(b) for b in blocked]})

@app.route('/api/blocked/websites')
@login_required
def list_blocked_websites():
    with get_db() as conn:
        blocked = conn.execute("SELECT * FROM blocked_websites ORDER BY blocked_at DESC").fetchall()
    return jsonify({'blocked': [dict(b) for b in blocked]})

@app.route('/api/blocked/ip/<int:block_id>/unblock', methods=['POST'])
@login_required
def unblock_ip(block_id):
    with get_db() as conn:
        record = conn.execute("SELECT * FROM blocked_ips WHERE id=?", (block_id,)).fetchone()
        if not record:
            return jsonify({'error': 'Block record not found'}), 404
        router_id = record['router_id']
        ip = record['ip']
        api = get_router_api(router_id)
        if api:
            rules = api.get_firewall_rules('filter')
            for rule in rules:
                if rule.get('comment', '').startswith(f'Blocked by Next Gen Pro - {ip}'):
                    api.remove_firewall_rule('filter', rule['.id'])
        conn.execute("DELETE FROM blocked_ips WHERE id=?", (block_id,))
        conn.commit()
    return jsonify({'success': True})

@app.route('/api/blocked/website/<int:block_id>/unblock', methods=['POST'])
@login_required
def unblock_website(block_id):
    with get_db() as conn:
        record = conn.execute("SELECT * FROM blocked_websites WHERE id=?", (block_id,)).fetchone()
        if not record:
            return jsonify({'error': 'Block record not found'}), 404
        router_id = record['router_id']
        website = record['website']
        api = get_router_api(router_id)
        if api:
            try:
                # Remove DNS static entry
                static_entries = api.run_command('/ip/dns/static/print')
                for entry in static_entries:
                    if entry.get('name') == website and entry.get('comment', '').startswith('Blocked by Next Gen Pro'):
                        api.run_command('/ip/dns/static/remove', {'.id': entry['.id']})
                        break
            except Exception as e:
                print(f"Unblock error: {e}")
        conn.execute("DELETE FROM blocked_websites WHERE id=?", (block_id,))
        conn.commit()
    return jsonify({'success': True})

# Configuration
@app.route('/api/router/<int:router_id>/config/<path:section>')
@login_required
def get_config(router_id, section):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    section_map = {
        'ip/address': '/ip/address/print',
        'ip/route': '/ip/route/print',
        'ip/dns': '/ip/dns/print',
        'ip/dhcp-server': '/ip/dhcp-server/print',
        'ip/dhcp-server/network': '/ip/dhcp-server/network/print',
        'ip/pool': '/ip/pool/print',
        'interface': '/interface/print',
        'interface/wireless': '/interface/wireless/print',
        'system/identity': '/system/identity/print',
        'system/clock': '/system/clock/print',
        'system/ntp-client': '/system/ntp-client/print',
        'user': '/user/print',
        'ip/service': '/ip/service/print',
        'ip/firewall/nat': '/ip/firewall/nat/print',
        'queue/simple': '/queue/simple/print',
    }
    command = section_map.get(section, f'/{section}/print')
    # Use safe_run with a 5-second per-command timeout so slow sections
    # (e.g. /ip/service on some RouterOS builds) never freeze the UI.
    result = api.safe_run(command, timeout=5)
    return jsonify({'data': result or [], 'section': section})

@app.route('/api/router/<int:router_id>/command', methods=['POST'])
@login_required
def run_command(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    command = data.get('command', '').strip()
    params = data.get('params', {})

    # Basic validation: must start with '/' and contain no shell-injection characters
    if not command:
        return jsonify({'error': 'No command provided'}), 400
    if not command.startswith('/'):
        return jsonify({'error': f"Invalid command '{command}'. RouterOS commands must start with '/'. Example: /system/resource/print"}), 400
    if any(c in command for c in (';', '&', '|', '`', '$', '\n', '\r')):
        return jsonify({'error': 'Command contains invalid characters'}), 400

    try:
        # Use a tight 5-second timeout so an unknown/slow command never freezes the UI
        result = api.talk(command, params if params else None, timeout=5)
        return jsonify({'result': result})
    except Exception as e:
        err = str(e)
        # RouterOS "no such command" trap → give a helpful message
        if 'no such command' in err.lower() or 'bad command' in err.lower():
            return jsonify({'error': f"Unknown command: '{command}'. Check the path and try again."}), 400
        return jsonify({'error': err}), 500

# Logs & Alerts
@app.route('/api/router/<int:router_id>/logs')
@login_required
def get_logs(router_id):
    api = get_router_api(router_id)
    if api:
        try:
            logs = api.get_logs()
            def _store(logs, router_id):
                try:
                    with get_db() as conn:
                        for log in logs[-50:]:
                            msg = log.get('message', '')
                            level = 'INFO'
                            if 'error' in msg.lower() or 'critical' in msg.lower():
                                level = 'CRITICAL'
                            elif 'warning' in msg.lower():
                                level = 'WARNING'
                            conn.execute("INSERT INTO logs (router_id, level, category, message) VALUES (?,?,?,?)",
                                        (router_id, level, log.get('topics', ''), msg))
                        conn.commit()
                except Exception:
                    pass
                for log in logs[-50:]:
                    siem.analyze_log({'message': log.get('message', '')}, router_id)
            threading.Thread(target=_store, args=(logs, router_id), daemon=True).start()
            enriched = []
            for log in logs:
                msg = log.get('message', '')
                t = log.get('time', '')
                topics = log.get('topics', '')
                level = 'INFO'
                if 'error' in msg.lower() or 'critical' in msg.lower():
                    level = 'CRITICAL'
                elif 'warning' in msg.lower():
                    level = 'WARNING'
                enriched.append({**log, 'level': level, 'human': _humanize_log(msg, t, topics)})
            return jsonify({'logs': enriched})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    try:
        with get_db() as conn:
            logs = conn.execute("SELECT * FROM logs WHERE router_id=? ORDER BY timestamp DESC LIMIT 200",
                                (router_id,)).fetchall()
        return jsonify({'logs': [dict(l) for l in logs]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _humanize_log(msg, t, topics):
    """Enhanced human-readable log formatter with user activity patterns"""
    import re
    msg_l = msg.lower()

    # Login events
    m = re.search(r'logged in from ([\d.]+)', msg_l)
    if m:
        ip = m.group(1)
        user = re.search(r'user (\w+)', msg_l)
        uname = user.group(1) if user else 'unknown'
        return f"User '{uname}' logged in from {ip} at {t}"
    if 'login failure' in msg_l or 'authentication failed' in msg_l:
        ip = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', msg)
        return f"Failed login attempt from {ip.group(1) if ip else 'unknown IP'} at {t}"
    if 'logged out' in msg_l:
        user = re.search(r'user (\w+)', msg_l)
        return f"User '{user.group(1) if user else 'unknown'}' logged out at {t}"

    # Application activity (WhatsApp, Facebook, Instagram)
    if 'whatsapp' in msg_l or 'facebook' in msg_l or 'instagram' in msg_l:
        app = 'WhatsApp' if 'whatsapp' in msg_l else 'Facebook' if 'facebook' in msg_l else 'Instagram'
        ip = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', msg)
        return f"User accessing {app} from {ip.group(1) if ip else 'device'}"

    # File downloads
    if '.exe' in msg_l or '.zip' in msg_l or '.msi' in msg_l or '.iso' in msg_l:
        file_match = re.search(r'([a-zA-Z0-9\-_]+\.(exe|zip|msi|iso))', msg_l)
        return f"User downloaded file: {file_match.group(1) if file_match else 'executable/archive'} at {t}"

    # Large data transfers
    if 'large' in msg_l and ('upload' in msg_l or 'download' in msg_l):
        size_match = re.search(r'(\d+(?:\.\d+)?)\s*(MB|GB|TB)', msg_l, re.IGNORECASE)
        if size_match:
            return f"User performed large data transfer: {size_match.group(1)} {size_match.group(2).upper()}"

    # Suspicious ports (P2P, gaming)
    suspicious_ports = {
        6881: 'BitTorrent', 6882: 'BitTorrent', 6969: 'BitTorrent',
        27015: 'Steam/CS:GO', 27036: 'Steam', 25565: 'Minecraft',
        3074: 'Xbox Live', 3658: 'PSN', 4664: 'eMule'
    }
    port_match = re.search(r'port (\d+)', msg_l)
    if port_match:
        port = int(port_match.group(1))
        if port in suspicious_ports:
            return f"Detected {suspicious_ports[port]} activity from {t}"

    # Multiple failed attempts (brute force)
    if 'login failure' in msg_l:
        ip = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', msg)
        attempts = re.search(r'(\d+)\s+attempts?', msg_l)
        if attempts:
            return f"⚠️ Suspicious: {attempts.group(1)} failed login attempts from {ip.group(1) if ip else 'unknown'}"

    # DHCP
    if 'bound' in msg_l and ('dhcp' in topics.lower() or 'dhcp' in msg_l):
        ip_m = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', msg)
        mac_m = re.search(r'([0-9A-Fa-f:]{17})', msg)
        return f"DHCP assigned {ip_m.group(1) if ip_m else '?'} to {mac_m.group(1) if mac_m else '?'} at {t}"

    # Firewall
    if 'forward' in msg_l or 'input' in msg_l or 'dropped' in msg_l:
        ip_m = re.search(r'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', msg)
        if 'drop' in msg_l:
            return f"🚫 Firewall blocked connection from {ip_m.group(1) if ip_m else 'unknown IP'}"
        return f"Firewall event: {msg} [{t}]"

    # Interface
    if 'link up' in msg_l:
        iface = re.search(r'(\w+) link up', msg_l)
        iname = iface.group(1).upper() if iface else 'Unknown'
        return f"✅ Interface {iname} came online at {t}"
    if 'link down' in msg_l:
        iface = re.search(r'(\w+) link down', msg_l)
        iname = iface.group(1).upper() if iface else 'Unknown'
        return f"⚠️ Interface {iname} went offline at {t}"

    # System startup/shutdown
    if 'started' in msg_l or 'rebooted' in msg_l:
        return f"🔄 Router was restarted at {t}"
    if 'shutdown' in msg_l:
        return f"🛑 Router was shut down at {t}"

    # Config change
    if 'changed' in msg_l or 'added' in msg_l or 'removed' in msg_l:
        return f"⚙️ Configuration change: {msg} at {t}"

    return f"{msg} [{t}]" if t else msg

@app.route('/api/alerts')
@login_required
def get_alerts():
    with get_db() as conn:
        alerts = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100").fetchall()
    return jsonify({'alerts': [dict(a) for a in alerts]})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    with get_db() as conn:
        conn.execute("UPDATE alerts SET is_resolved=1 WHERE id=?", (alert_id,))
        conn.commit()
    return jsonify({'success': True})

# Dashboard - OPTIMIZED with parallel API calls
@app.route('/api/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        routers = conn.execute("SELECT * FROM routers WHERE status='connected' ORDER BY last_seen DESC").fetchall()
        active_alerts = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE is_resolved=0").fetchone()
        total_devices = conn.execute("SELECT COUNT(DISTINCT mac) as count FROM devices").fetchone()
        recent_alerts = conn.execute("SELECT * FROM alerts WHERE is_resolved=0 ORDER BY timestamp DESC LIMIT 10").fetchall()
        bandwidth = conn.execute("SELECT * FROM bandwidth_history ORDER BY timestamp DESC LIMIT 60").fetchall()
        critical_count = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE severity='CRITICAL' AND is_resolved=0").fetchone()
        warning_count = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE severity='WARNING' AND is_resolved=0").fetchone()
    
    # Function to fetch live data for a single router (used in parallel)
    def fetch_live_data(router):
        rd = dict(router)
        api = get_router_api(rd['id'])
        if api:
            try:
                res = api.get_resources()
                if res:
                    rv = res[0]
                    total_mem = int(rv.get('total-memory', 0))
                    free_mem = int(rv.get('free-memory', 0))
                    used_mem = total_mem - free_mem
                    rd['cpu_load'] = int(rv.get('cpu-load', rd.get('cpu_load', 0)))
                    rd['memory_used'] = _calc_memory_pct(str(total_mem), str(free_mem))
                    rd['memory_used_mb'] = round(used_mem / 1024 / 1024, 1)
                    rd['memory_total_mb'] = round(total_mem / 1024 / 1024, 1)
                    rd['memory_free_mb'] = round(free_mem / 1024 / 1024, 1)
                    rd['uptime'] = rv.get('uptime', rd.get('uptime', ''))
                    rd['cpu_count'] = rv.get('cpu-count', 1)
                    rd['cpu_frequency'] = rv.get('cpu-frequency', '')
                    rd['architecture'] = rv.get('architecture-name', '')
            except Exception:
                pass
        return rd
    
    # Parallel execution for all connected routers
    router_list = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_live_data, router): router for router in routers}
        for future in as_completed(futures):
            router_list.append(future.result())
    
    return jsonify({
        'routers': router_list,
        'active_alerts': active_alerts['count'],
        'total_devices': total_devices['count'],
        'recent_alerts': [dict(a) for a in recent_alerts],
        'bandwidth': [dict(b) for b in bandwidth],
        'critical_alerts': critical_count['count'],
        'warning_alerts': warning_count['count'],
        'connected_routers': len(router_connections),
    })

@app.route('/api/router/<int:router_id>/delete', methods=['DELETE'])
@login_required
def delete_router(router_id):
    if router_id in router_connections:
        try: router_connections[router_id].disconnect()
        except: pass
        del router_connections[router_id]
    with get_db() as conn:
        conn.execute('DELETE FROM routers WHERE id=?', (router_id,))
        conn.execute('DELETE FROM devices WHERE router_id=?', (router_id,))
        conn.execute('DELETE FROM logs WHERE router_id=?', (router_id,))
        conn.execute('DELETE FROM alerts WHERE router_id=?', (router_id,))
        conn.execute('DELETE FROM bandwidth_history WHERE router_id=?', (router_id,))
        conn.execute('DELETE FROM interface_bandwidth WHERE router_id=?', (router_id,))
        conn.commit()
    return jsonify({'success': True})

# All routers
@app.route('/api/routers')
@login_required
def list_routers():
    with get_db() as conn:
        routers = conn.execute("SELECT * FROM routers ORDER BY last_seen DESC").fetchall()
    return jsonify({'routers': [dict(r) for r in routers]})

# Router history
@app.route('/api/routers/history')
@login_required
def router_history():
    with get_db() as conn:
        routers = conn.execute("SELECT * FROM routers WHERE status='disconnected' ORDER BY last_seen DESC LIMIT 50").fetchall()
    return jsonify({'routers': [dict(r) for r in routers]})

# ------------------- NEW ENDPOINTS FOR ENHANCED FEATURES -------------------

# Real-time bandwidth rates per interface
@app.route('/api/router/<int:router_id>/bandwidth/now', methods=['GET'])
@login_required
def get_realtime_bandwidth(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        interfaces = api.get_interfaces()
        results = []
        for iface in interfaces:
            iface_name = iface.get('name', '')
            if not iface_name:
                continue
            results.append({
                'name': iface_name,
                'rx_bps': int(iface.get('rx-rate', 0)),
                'tx_bps': int(iface.get('tx-rate', 0)),
                'rx_bytes_total': int(iface.get('rx-byte', 0)),
                'tx_bytes_total': int(iface.get('tx-byte', 0)),
                'running': iface.get('running', False)
            })
        return jsonify({'interfaces': results, 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Top talkers (based on connection tracking)
@app.route('/api/router/<int:router_id>/top-talkers', methods=['GET'])
@login_required
def get_top_talkers(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        connections = api.run_command('/ip/firewall/connection/print')
        talkers = defaultdict(lambda: {'rx_bytes': 0, 'tx_bytes': 0, 'connections': 0})
        for conn in connections:
            src_ip = conn.get('src-address', '').split(':')[0]
            if not src_ip or src_ip.startswith('0.0.0.0'):
                continue
            talkers[src_ip]['connections'] += 1
            talkers[src_ip]['rx_bytes'] += int(conn.get('rx-byte', 0))
            talkers[src_ip]['tx_bytes'] += int(conn.get('tx-byte', 0))
        sorted_talkers = sorted(
            [{'ip': ip, **stats} for ip, stats in talkers.items()],
            key=lambda x: x['rx_bytes'] + x['tx_bytes'],
            reverse=True
        )[:20]
        return jsonify({'top_talkers': sorted_talkers, 'total_connections': len(connections)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Activity timeline (human readable)
@app.route('/api/activity/timeline', methods=['GET'])
@login_required
def get_activity_timeline():
    with get_db() as conn:
        logs = conn.execute("""
            SELECT l.*, r.name as router_name 
            FROM logs l 
            JOIN routers r ON l.router_id = r.id 
            ORDER BY l.timestamp DESC 
            LIMIT 200
        """).fetchall()
        alerts = conn.execute("""
            SELECT a.*, r.name as router_name 
            FROM alerts a 
            JOIN routers r ON a.router_id = r.id 
            WHERE a.is_resolved = 0
            ORDER BY a.timestamp DESC 
            LIMIT 50
        """).fetchall()
    timeline = []
    for log in logs:
        timeline.append({
            'timestamp': log['timestamp'],
            'type': 'log',
            'router': log['router_name'],
            'level': log['level'],
            'message': log['message'],
            'human': _humanize_log(log['message'], log['timestamp'], log.get('category', ''))
        })
    for alert in alerts:
        timeline.append({
            'timestamp': alert['timestamp'],
            'type': 'alert',
            'router': alert['router_name'],
            'severity': alert['severity'],
            'title': alert['title'],
            'description': alert['description'],
            'human': f"[{alert['severity']}] {alert['title']}: {alert['description']}"
        })
    timeline.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'timeline': timeline[:100]})

# Web proxy and DNS logging (optional enable/disable)
@app.route('/api/router/<int:router_id>/web-proxy/enable', methods=['POST'])
@login_required
def enable_web_proxy(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    data = request.json
    proxy_port = data.get('port', 8080)
    try:
        api.run_command('/ip/proxy/set', {
            'enabled': 'yes',
            'port': proxy_port,
            'cache-administrator': 'admin',
            'max-cache-size': '500MiB',
            'src-address': '0.0.0.0'
        })
        api.talk('/ip/firewall/nat/add', {
            'chain': 'dstnat',
            'protocol': 'tcp',
            'dst-port': '80',
            'action': 'redirect',
            'to-ports': proxy_port,
            'comment': 'Transparent HTTP Proxy - Next Gen Pro'
        })
        api.run_command('/system/logging/add', {
            'topics': 'web-proxy,!debug',
            'action': 'memory'
        })
        return jsonify({'success': True, 'message': f'Web proxy enabled on port {proxy_port}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/router/<int:router_id>/web-activity', methods=['GET'])
@login_required
def get_web_activity(router_id):
    api = get_router_api(router_id)
    if not api:
        return jsonify({'error': 'Router not connected'}), 400
    try:
        logs = api.run_command('/log/print')
        proxy_logs = []
        for log in logs:
            topics = log.get('topics', '')
            message = log.get('message', '')
            if 'web-proxy' in topics or 'dns' in topics:
                proxy_logs.append({
                    'timestamp': log.get('time', ''),
                    'topics': topics,
                    'message': message,
                    'human': _humanize_web_log(message)
                })
        # Also show active web connections (ports 80/443)
        connections = api.run_command('/ip/firewall/connection/print')
        web_connections = []
        for conn in connections:
            dst_port = conn.get('dst-port', '')
            if dst_port in ['80', '443', '8080', '3128']:
                web_connections.append({
                    'src_ip': conn.get('src-address', '').split(':')[0],
                    'dst_ip': conn.get('dst-address', '').split(':')[0],
                    'dst_port': dst_port,
                    'protocol': conn.get('protocol', 'tcp'),
                    'state': conn.get('tcp-state', ''),
                    'rx_bytes': conn.get('rx-byte', 0),
                    'tx_bytes': conn.get('tx-byte', 0)
                })
        return jsonify({
            'proxy_logs': proxy_logs[-100:],
            'active_web_connections': web_connections,
            'note': 'HTTPS URLs require additional configuration (SSL inspection)'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _humanize_web_log(message):
    """Convert raw web proxy log to human-readable activity"""
    import re
    message_l = message.lower()
    get_match = re.search(r'GET (https?://[^\s]+)', message, re.IGNORECASE)
    if get_match:
        return f"User requested: {get_match.group(1)}"
    dns_match = re.search(r'query\s+([a-zA-Z0-9\.\-]+)', message_l)
    if dns_match:
        return f"User looked up: {dns_match.group(1)}"
    if 'blocked' in message_l and 'website' in message_l:
        site_match = re.search(r'blocked\s+([a-zA-Z0-9\.\-]+)', message_l)
        return f"Attempt to access blocked site: {site_match.group(1) if site_match else 'unknown'}"
    if 'cache hit' in message_l:
        return f"Served from cache: {message}"
    if 'cache miss' in message_l:
        return f"Fetched from internet: {message}"
    return f"Web activity: {message}"

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🚀  Next Gen Pro - Next Generation Network Security  🚀     ║
    ║                                                               ║
    ║   AI-Powered SIEM + Advanced MikroTik Management              ║
    ║                                                               ║
    ║   🌐 Access: http://localhost:5000                             ║
    ║   👤 Default Login: admin / admin                              ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    import logging
    log = logging.getLogger('werkzeug')
    # Remove the "WARNING: This is a development server" line only
    _orig_info = log.info
    def _filtered_info(msg, *args, **kwargs):
        if 'development server' in str(msg) or 'production' in str(msg).lower():
            return
        _orig_info(msg, *args, **kwargs)
    log.info = _filtered_info
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)