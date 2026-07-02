"""WatchDog - Local Logging Module (SQLite)"""

import os
import sqlite3
import json
from datetime import datetime


class Logger:
    """Logs alert data to a local SQLite database."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.db')
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                hostname TEXT,
                username TEXT,
                public_ip TEXT,
                private_ip TEXT,
                mac_address TEXT,
                os_system TEXT,
                geolocation TEXT,
                wifi_ssid TEXT,
                canary_name TEXT,
                file_hash TEXT,
                hash_match INTEGER,
                raw_data TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_alert(self, data, canary_name=None, file_hash=None, hash_match=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, hostname, username, public_ip, private_ip,
                              mac_address, os_system, geolocation, wifi_ssid,
                              canary_name, file_hash, hash_match, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('timestamp', datetime.now().isoformat()),
            data.get('hostname'),
            data.get('username'),
            data.get('public_ip'),
            data.get('private_ip'),
            data.get('mac_address'),
            data.get('os_system'),
            data.get('geolocation'),
            data.get('wifi_ssid'),
            canary_name,
            file_hash,
            1 if hash_match else 0,
            json.dumps(data, default=str)
        ))
        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        return alert_id

    def get_alerts(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_alert_count(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts')
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def search_alerts(self, hostname=None, username=None, ip=None):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = 'SELECT * FROM alerts WHERE 1=1'
        params = []

        if hostname:
            query += ' AND hostname LIKE ?'
            params.append(f'%{hostname}%')
        if username:
            query += ' AND username LIKE ?'
            params.append(f'%{username}%')
        if ip:
            query += ' AND (public_ip LIKE ? OR private_ip LIKE ?)'
            params.extend([f'%{ip}%', f'%{ip}%'])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def clear_alerts(self):
        """Clear all alerts from the local database.

        This is an administrative function for managing the local alert database.
        Only the system administrator who owns this system should use this.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
