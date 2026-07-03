"""WatchDog - DNS Canary Module

Detects DNS hijacking by monitoring DNS resolution of canary domains.
Creates fake DNS records that alert when queried.
"""

import os
import socket
import json
import hashlib
import secrets
from datetime import datetime


class DNSCanary:
    """DNS-based canary for detecting DNS hijacking."""

    def __init__(self, config=None):
        self.config = config or {}
        self.dns_config = self.config.get('dns_canary', {})
        self.canaries = {}
        self._load_canaries()

    def _canaries_path(self):
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dns_canaries.json')

    def _load_canaries(self):
        path = self._canaries_path()
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.canaries = json.load(f)

    def _save_canaries(self):
        with open(self._canaries_path(), 'w') as f:
            json.dump(self.canaries, f, indent=2)

    def create_canary(self, domain, subdomain=None, record_type='A'):
        """Create a DNS canary record."""
        if subdomain is None:
            subdomain = f"canary-{secrets.token_hex(8)}"

        canary_id = hashlib.sha256(f"{domain}:{subdomain}".encode()).hexdigest()[:16]

        canary_data = {
            'id': canary_id,
            'domain': domain,
            'subdomain': subdomain,
            'full_domain': f"{subdomain}.{domain}",
            'record_type': record_type,
            'created_at': datetime.now().isoformat(),
            'last_checked': None,
            'last_resolved': None,
            'check_count': 0,
            'is_triggered': False,
            'expected_ip': self._get_expected_ip(),
            'triggers': []
        }

        self.canaries[canary_id] = canary_data
        self._save_canaries()

        return canary_data

    def _get_expected_ip(self):
        """Get the expected IP for this canary (should be non-routable or specific)."""
        return self.dns_config.get('expected_ip', '192.0.2.1')

    def check_canary(self, canary_id):
        """Check if DNS canary has been resolved."""
        canary = self.canaries.get(canary_id)
        if not canary:
            return None

        domain = canary['full_domain']
        canary['check_count'] += 1
        canary['last_checked'] = datetime.now().isoformat()

        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            pass

        if resolved_ip:
            canary['last_resolved'] = datetime.now().isoformat()

            if resolved_ip != canary['expected_ip']:
                canary['is_triggered'] = True
                canary['triggers'].append({
                    'timestamp': datetime.now().isoformat(),
                    'resolved_ip': resolved_ip,
                    'expected_ip': canary['expected_ip'],
                    'query_source': self._detect_query_source()
                })

        self._save_canaries()
        return canary

    def _detect_query_source(self):
        """Try to detect where the DNS query came from."""
        return {
            'note': 'DNS hijacking detected - query not from expected source'
        }

    def check_all_canaries(self):
        """Check all active canaries."""
        results = []
        for canary_id, canary in list(self.canaries.items()):
            if not canary.get('is_triggered'):
                result = self.check_canary(canary_id)
                if result:
                    results.append(result)
        return results

    def get_canary(self, canary_id):
        return self.canaries.get(canary_id)

    def get_all_canaries(self, active_only=True):
        if active_only:
            return {k: v for k, v in self.canaries.items() if not v.get('is_triggered')}
        return self.canaries

    def get_triggered_canaries(self):
        return {k: v for k, v in self.canaries.items() if v.get('is_triggered')}

    def deactivate_canary(self, canary_id):
        if canary_id in self.canaries:
            del self.canaries[canary_id]
            self._save_canaries()
            return True
        return False

    def get_dns_records_template(self, canary):
        """Generate DNS records that need to be created."""
        domain = canary['full_domain']
        expected_ip = canary['expected_ip']

        records = {
            'A': {
                'name': domain,
                'type': 'A',
                'value': expected_ip,
                'ttl': 300
            },
            'TXT': {
                'name': f"_canary.{domain}",
                'type': 'TXT',
                'value': f"WatchDog-verify={canary['id']}",
                'ttl': 300
            }
        }

        return records

    def format_alert(self, canary, trigger_info=None):
        """Format DNS canary trigger for alerts."""
        lines = [
            f"DNS Canary Triggered: {canary.get('full_domain')}",
            f"Record Type: {canary.get('record_type')}",
            f"Created: {canary.get('created_at')}",
        ]

        if trigger_info:
            lines.append(f"Triggered At: {trigger_info.get('timestamp')}")
            lines.append(f"Resolved IP: {trigger_info.get('resolved_ip')}")
            lines.append(f"Expected IP: {trigger_info.get('expected_ip')}")

        lines.append("\nThis indicates DNS hijacking or poisoning!")
        lines.append("An attacker may be redirecting traffic from your domain.")

        return '\n'.join(lines)

    def setup_instructions(self, canary):
        """Generate setup instructions for DNS provider."""
        records = self.get_dns_records_template(canary)

        instructions = [
            f"DNS Canary Setup for {canary['full_domain']}",
            "=" * 50,
            "",
            "Add the following DNS records to your domain:",
            "",
        ]

        for record_type, record in records.items():
            instructions.append(f"Record Type: {record['type']}")
            instructions.append(f"  Name: {record['name']}")
            instructions.append(f"  Value: {record['value']}")
            instructions.append(f"  TTL: {record['ttl']}")
            instructions.append("")

        instructions.extend([
            "After creating records, test with:",
            f"  nslookup {canary['full_domain']}",
            f"  dig {canary['full_domain']}",
            "",
            "The canary will alert if DNS resolution changes from expected IP."
        ])

        return '\n'.join(instructions)


class DNSMonitor:
    """Monitors DNS resolution for anomalies."""

    def __init__(self, config=None):
        self.config = config or {}
        self.baseline = {}

    def record_baseline(self, domain):
        """Record baseline DNS resolution for a domain."""
        try:
            ip = socket.gethostbyname(domain)
            self.baseline[domain] = {
                'ip': ip,
                'timestamp': datetime.now().isoformat()
            }
            return ip
        except socket.gaierror:
            return None

    def check_deviation(self, domain):
        """Check if DNS resolution has deviated from baseline."""
        if domain not in self.baseline:
            return None

        try:
            current_ip = socket.gethostbyname(domain)
            baseline_ip = self.baseline[domain]['ip']

            if current_ip != baseline_ip:
                return {
                    'domain': domain,
                    'baseline_ip': baseline_ip,
                    'current_ip': current_ip,
                    'deviated': True,
                    'timestamp': datetime.now().isoformat()
                }
        except socket.gaierror:
            pass

        return {'domain': domain, 'deviated': False}

    def monitor_domains(self, domains):
        """Monitor multiple domains for DNS changes."""
        results = []
        for domain in domains:
            result = self.check_deviation(domain)
            if result and result.get('deviated'):
                results.append(result)
        return results
