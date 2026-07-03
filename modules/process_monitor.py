"""WatchDog - Process Monitor Module

DEFENSIVE DETECTION: This module identifies unauthorized security tools
running on monitored systems. It is designed for defensive security monitoring
only, not for offensive operations.

Detects suspicious processes running on the system when canary is triggered.
Identifies hacking tools, analysis tools, and suspicious activity.
"""

import os
import json
import psutil
from datetime import datetime


class ProcessMonitor:
    """Monitors and analyzes running processes for suspicious activity.

    This is a DEFENSIVE SECURITY MODULE for authorized monitoring only.
    It detects unauthorized security tools on systems you own.
    """

    def __init__(self):
        self.suspicious_processes = self._load_process_signatures()
        self.suspicious_patterns = [
            'powershell -enc', 'powershell -e ',
            'wmic process call create',
            'schtasks /create',
            'reg add', 'reg save',
            'ntdsutil',
            'vssadmin delete',
            'bcdedit',
            'wevtutil cl',
        ]

    def _load_process_signatures(self):
        """Load suspicious process signatures from external config file."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'suspicious_processes.json'
        )

        default_signatures = {
            'hacking_tools': [],
            'analysis_tools': [],
            'suspicious_tools': []
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    return {
                        'hacking_tools': data.get('hacking_tools', []),
                        'analysis_tools': data.get('analysis_tools', []),
                        'suspicious_tools': data.get('suspicious_tools', [])
                    }
            except Exception:
                return default_signatures

        return default_signatures

    def get_all_processes(self):
        """Get all running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time', 'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                processes.append({
                    'pid': info.get('pid'),
                    'name': info.get('name', ''),
                    'username': info.get('username', ''),
                    'cmdline': ' '.join(info.get('cmdline', []) or []),
                    'create_time': info.get('create_time'),
                    'cpu_percent': info.get('cpu_percent', 0),
                    'memory_mb': info.get('memory_info', {}).rss / 1024 / 1024 if info.get('memory_info') else 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    def detect_suspicious(self):
        """Detect suspicious processes.

        Returns findings of unauthorized security tools on the system.
        """
        processes = self.get_all_processes()
        findings = {
            'hacking_tools': [],
            'analysis_tools': [],
            'suspicious_tools': [],
            'suspicious_commands': [],
            'total_processes': len(processes)
        }

        for proc in processes:
            name_lower = proc['name'].lower()
            cmdline_lower = proc['cmdline'].lower()

            for tool in self.suspicious_processes['hacking_tools']:
                if tool.lower() in name_lower:
                    findings['hacking_tools'].append(proc)

            for tool in self.suspicious_processes['analysis_tools']:
                if tool.lower() in name_lower:
                    findings['analysis_tools'].append(proc)

            for tool in self.suspicious_processes['suspicious_tools']:
                if tool.lower() in name_lower:
                    findings['suspicious_tools'].append(proc)

            for pattern in self.suspicious_patterns:
                if pattern.lower() in cmdline_lower:
                    findings['suspicious_commands'].append({
                        'process': proc,
                        'pattern': pattern
                    })

        return findings

    def get_process_snapshot(self):
        """Get a snapshot of current processes for logging."""
        processes = self.get_all_processes()
        return {
            'timestamp': datetime.now().isoformat(),
            'total_processes': len(processes),
            'top_cpu': sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:10],
            'top_memory': sorted(processes, key=lambda x: x.get('memory_mb', 0), reverse=True)[:10]
        }

    def format_findings(self, findings):
        """Format process findings for alerts."""
        lines = ['Process Analysis:']

        if findings.get('hacking_tools'):
            lines.append(f"\n[CRITICAL] Unauthorized Security Tools Detected ({len(findings['hacking_tools'])}):")
            for proc in findings['hacking_tools']:
                lines.append(f"  - {proc['name']} (PID: {proc['pid']}, User: {proc['username']})")

        if findings.get('analysis_tools'):
            lines.append(f"\n[WARNING] Analysis Tools Detected ({len(findings['analysis_tools'])}):")
            for proc in findings['analysis_tools']:
                lines.append(f"  - {proc['name']} (PID: {proc['pid']}, User: {proc['username']})")

        if findings.get('suspicious_tools'):
            lines.append(f"\n[WARNING] Suspicious Tools Detected ({len(findings['suspicious_tools'])}):")
            for proc in findings['suspicious_tools']:
                lines.append(f"  - {proc['name']} (PID: {proc['pid']}, User: {proc['username']})")

        if findings.get('suspicious_commands'):
            lines.append(f"\n[INFO] Suspicious Commands ({len(findings['suspicious_commands'])}):")
            for item in findings['suspicious_commands'][:5]:
                lines.append(f"  - {item['process']['name']}: {item['pattern']}")

        if not any([findings.get('hacking_tools'), findings.get('analysis_tools'),
                    findings.get('suspicious_tools'), findings.get('suspicious_commands')]):
            lines.append("No unauthorized security tools detected")

        return '\n'.join(lines)

    def is_security_tool_running(self):
        """Check if any unauthorized security/analysis tools are currently running."""
        findings = self.detect_suspicious()
        return bool(findings.get('hacking_tools') or findings.get('analysis_tools'))
