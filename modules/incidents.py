"""WatchDog - Incident Management Module

Groups multiple triggers from the same source into incidents
for better alert management and reduced noise.
"""

import os
import sqlite3
import json
from datetime import datetime, timedelta


class IncidentManager:
    """Manages incident grouping and lifecycle."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.db')
        self.db_path = db_path
        self.grouping_window = 3600
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT,
                status TEXT DEFAULT 'open',
                severity TEXT DEFAULT 'medium',
                source_ip TEXT,
                first_seen TEXT,
                last_seen TEXT,
                alert_count INTEGER DEFAULT 0,
                assigned_to TEXT,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                alert_id INTEGER,
                added_at TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents(incident_id),
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            )
        ''')
        conn.commit()
        conn.close()

    def _generate_incident_id(self):
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        import random
        random_suffix = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
        return f'INC-{timestamp}-{random_suffix}'

    def find_or_create_incident(self, alert_data, alert_id):
        """Find existing incident for this source or create new one."""
        source_ip = alert_data.get('public_ip', '')
        hostname = alert_data.get('hostname', '')
        username = alert_data.get('username', '')

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(seconds=self.grouping_window)).isoformat()

        cursor.execute('''
            SELECT incident_id FROM incidents
            WHERE source_ip = ?
            AND status = 'open'
            AND last_seen > ?
            ORDER BY last_seen DESC LIMIT 1
        ''', (source_ip, cutoff))

        row = cursor.fetchone()

        if row:
            incident_id = row[0]
            cursor.execute('''
                UPDATE incidents
                SET alert_count = alert_count + 1, last_seen = ?, updated_at = ?
                WHERE incident_id = ?
            ''', (datetime.now().isoformat(), datetime.now().isoformat(), incident_id))

            cursor.execute('''
                INSERT INTO incident_alerts (incident_id, alert_id, added_at)
                VALUES (?, ?, ?)
            ''', (incident_id, alert_id, datetime.now().isoformat()))

            self._update_severity(cursor, incident_id)
        else:
            incident_id = self._generate_incident_id()
            title = self._generate_title(alert_data)

            cursor.execute('''
                INSERT INTO incidents (incident_id, title, status, severity, source_ip,
                                     first_seen, last_seen, alert_count, created_at, updated_at)
                VALUES (?, ?, 'open', 'medium', ?, ?, ?, 1, ?, ?)
            ''', (
                incident_id, title, source_ip,
                datetime.now().isoformat(), datetime.now().isoformat(),
                datetime.now().isoformat(), datetime.now().isoformat()
            ))

            cursor.execute('''
                INSERT INTO incident_alerts (incident_id, alert_id, added_at)
                VALUES (?, ?, ?)
            ''', (incident_id, alert_id, datetime.now().isoformat()))

        conn.commit()
        conn.close()

        return incident_id

    def _generate_title(self, alert_data):
        username = alert_data.get('username', 'unknown')
        hostname = alert_data.get('hostname', 'unknown')
        return f"Canary triggered by {username}@{hostname}"

    def _update_severity(self, cursor, incident_id):
        cursor.execute('SELECT alert_count FROM incidents WHERE incident_id = ?', (incident_id,))
        row = cursor.fetchone()
        if row:
            count = row[0]
            if count >= 10:
                severity = 'critical'
            elif count >= 5:
                severity = 'high'
            elif count >= 2:
                severity = 'medium'
            else:
                severity = 'low'

            cursor.execute('''
                UPDATE incidents SET severity = ?, updated_at = ?
                WHERE incident_id = ?
            ''', (severity, datetime.now().isoformat(), incident_id))

    def get_incident(self, incident_id):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM incidents WHERE incident_id = ?', (incident_id,))
        row = cursor.fetchone()
        incident = dict(row) if row else None

        if incident:
            cursor.execute('''
                SELECT a.* FROM alerts a
                JOIN incident_alerts ia ON a.id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.timestamp
            ''', (incident_id,))
            incident['alerts'] = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return incident

    def get_open_incidents(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM incidents
            WHERE status = 'open'
            ORDER BY last_seen DESC
            LIMIT ?
        ''', (limit,))

        incidents = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return incidents

    def update_status(self, incident_id, status, notes=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE incidents
            SET status = ?, notes = ?, updated_at = ?
            WHERE incident_id = ?
        ''', (status, notes, datetime.now().isoformat(), incident_id))

        conn.commit()
        conn.close()

    def assign_incident(self, incident_id, assigned_to):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE incidents
            SET assigned_to = ?, updated_at = ?
            WHERE incident_id = ?
        ''', (assigned_to, datetime.now().isoformat(), incident_id))

        conn.commit()
        conn.close()

    def get_incident_stats(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        stats['open'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'closed'")
        stats['closed'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND status = 'open'")
        stats['critical'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'high' AND status = 'open'")
        stats['high'] = cursor.fetchone()[0]

        conn.close()
        return stats

    def format_incident(self, incident):
        """Format incident for display."""
        lines = [
            f"Incident: {incident.get('incident_id')}",
            f"Title: {incident.get('title')}",
            f"Status: {incident.get('status')}",
            f"Severity: {incident.get('severity')}",
            f"Source IP: {incident.get('source_ip')}",
            f"Alerts: {incident.get('alert_count')}",
            f"First Seen: {incident.get('first_seen')}",
            f"Last Seen: {incident.get('last_seen')}",
        ]
        if incident.get('assigned_to'):
            lines.append(f"Assigned: {incident.get('assigned_to')}")
        return '\n'.join(lines)
