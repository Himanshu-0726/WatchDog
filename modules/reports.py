"""WatchDog - Scheduled Reports Module

Generates and sends daily/weekly/monthly summary reports
of all canary activity and security events.
"""

import os
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta


class ReportGenerator:
    """Generates security summary reports."""

    def __init__(self, config=None):
        self.config = config or {}
        self.report_config = self.config.get('reports', {})
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alerts.db')

    def generate_daily_report(self):
        """Generate a daily summary report."""
        return self._generate_report('daily', 1)

    def generate_weekly_report(self):
        """Generate a weekly summary report."""
        return self._generate_report('weekly', 7)

    def generate_monthly_report(self):
        """Generate a monthly summary report."""
        return self._generate_report('monthly', 30)

    def _generate_report(self, period, days):
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COUNT(*) as total,
                   COUNT(DISTINCT public_ip) as unique_ips,
                   COUNT(DISTINCT hostname) as unique_hosts,
                   COUNT(DISTINCT username) as unique_users
            FROM alerts WHERE timestamp > ?
        ''', (cutoff,))
        summary = dict(cursor.fetchone())

        cursor.execute('''
            SELECT * FROM alerts WHERE timestamp > ?
            ORDER BY timestamp DESC LIMIT 100
        ''', (cutoff,))
        recent_alerts = [dict(row) for row in cursor.fetchall()]

        cursor.execute('''
            SELECT public_ip, COUNT(*) as count
            FROM alerts WHERE timestamp > ?
            GROUP BY public_ip ORDER BY count DESC LIMIT 10
        ''', (cutoff,))
        top_ips = [dict(row) for row in cursor.fetchall()]

        cursor.execute('''
            SELECT hostname, COUNT(*) as count
            FROM alerts WHERE timestamp > ?
            GROUP BY hostname ORDER BY count DESC LIMIT 10
        ''', (cutoff,))
        top_hosts = [dict(row) for row in cursor.fetchall()]

        cursor.execute('''
            SELECT username, COUNT(*) as count
            FROM alerts WHERE timestamp > ?
            GROUP BY username ORDER BY count DESC LIMIT 10
        ''', (cutoff,))
        top_users = [dict(row) for row in cursor.fetchall()]

        conn.close()

        report = {
            'period': period,
            'generated_at': datetime.now().isoformat(),
            'summary': summary,
            'recent_alerts': recent_alerts,
            'top_ips': top_ips,
            'top_hosts': top_hosts,
            'top_users': top_users,
            'days_covered': days
        }

        return report

    def format_text_report(self, report):
        """Format report as plain text."""
        lines = [
            "=" * 60,
            f"WatchDog {report['period'].upper()} REPORT",
            "=" * 60,
            f"Generated: {report['generated_at']}",
            f"Period: Last {report['days_covered']} day(s)",
            "",
            "SUMMARY",
            "-" * 40,
            f"Total Alerts: {report['summary']['total']}",
            f"Unique IPs: {report['summary']['unique_ips']}",
            f"Unique Hosts: {report['summary']['unique_hosts']}",
            f"Unique Users: {report['summary']['unique_users']}",
            "",
        ]

        if report.get('top_ips'):
            lines.append("TOP IPs BY ALERT COUNT")
            lines.append("-" * 40)
            for item in report['top_ips']:
                lines.append(f"  {item['public_ip']}: {item['count']} alerts")
            lines.append("")

        if report.get('top_hosts'):
            lines.append("TOP HOSTS BY ALERT COUNT")
            lines.append("-" * 40)
            for item in report['top_hosts']:
                lines.append(f"  {item['hostname']}: {item['count']} alerts")
            lines.append("")

        if report.get('top_users'):
            lines.append("TOP USERS BY ALERT COUNT")
            lines.append("-" * 40)
            for item in report['top_users']:
                lines.append(f"  {item['username']}: {item['count']} alerts")
            lines.append("")

        if report.get('recent_alerts'):
            lines.append("RECENT ALERTS (Last 10)")
            lines.append("-" * 40)
            for alert in report['recent_alerts'][:10]:
                lines.append(f"  [{alert['timestamp']}] {alert['username']}@{alert['hostname']} ({alert['public_ip']})")

        return '\n'.join(lines)

    def format_html_report(self, report):
        """Format report as HTML email."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #ff6600; color: white; padding: 20px; text-align: center; }}
        .summary {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        .summary h3 {{ margin-top: 0; }}
        .stat {{ display: inline-block; margin: 10px 20px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #ff6600; }}
        .stat-label {{ font-size: 12px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #ff6600; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WatchDog {report['period'].title()} Report</h1>
        <p>Generated: {report['generated_at']}</p>
    </div>

    <div class="summary">
        <h3>Summary</h3>
        <div class="stat">
            <div class="stat-value">{report['summary']['total']}</div>
            <div class="stat-label">Total Alerts</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report['summary']['unique_ips']}</div>
            <div class="stat-label">Unique IPs</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report['summary']['unique_hosts']}</div>
            <div class="stat-label">Unique Hosts</div>
        </div>
        <div class="stat">
            <div class="stat-value">{report['summary']['unique_users']}</div>
            <div class="stat-label">Unique Users</div>
        </div>
    </div>
"""

        if report.get('top_ips'):
            html += """
    <h3>Top IPs</h3>
    <table>
        <tr><th>IP Address</th><th>Alert Count</th></tr>
"""
            for item in report['top_ips']:
                html += f"        <tr><td>{item['public_ip']}</td><td>{item['count']}</td></tr>\n"
            html += "    </table>\n"

        if report.get('recent_alerts'):
            html += """
    <h3>Recent Alerts</h3>
    <table>
        <tr><th>Time</th><th>User</th><th>Host</th><th>IP</th></tr>
"""
            for alert in report['recent_alerts'][:10]:
                html += f"        <tr><td>{alert['timestamp']}</td><td>{alert['username']}</td><td>{alert['hostname']}</td><td>{alert['public_ip']}</td></tr>\n"
            html += "    </table>\n"

        html += """
</body>
</html>
"""
        return html


class EmailReporter:
    """Sends reports via email."""

    def __init__(self, config=None):
        self.config = config or {}
        self.smtp_config = self.config.get('smtp', {})

    def send_report(self, report_text, subject=None, html=None):
        if not self.smtp_config.get('enabled'):
            return {'status': 'disabled'}

        smtp_server = self.smtp_config.get('server', '')
        smtp_port = self.smtp_config.get('port', 587)
        smtp_user = self.smtp_config.get('username', '')
        smtp_pass = self.smtp_config.get('password', '')
        from_addr = self.smtp_config.get('from_email', smtp_user)
        to_addrs = self.smtp_config.get('to_emails', [])

        if not all([smtp_server, smtp_user, smtp_pass, to_addrs]):
            return {'status': 'misconfigured'}

        if subject is None:
            subject = f"WatchDog Report - {datetime.now().strftime('%Y-%m-%d')}"

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_addr
            msg['To'] = ', '.join(to_addrs)

            msg.attach(MIMEText(report_text, 'plain'))

            if html:
                msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

            return {'status': 'sent', 'recipients': to_addrs}

        except Exception as e:
            return {'status': 'error', 'message': str(e)}
