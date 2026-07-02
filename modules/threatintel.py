"""WatchDog - Threat Intelligence Module

Integrates with VirusTotal, AbuseIPDB, and other threat intel feeds
to enrich alert data with reputation information.
"""

import os
import requests
from datetime import datetime


class ThreatIntel:
    """Threat intelligence integration for IP reputation checking."""

    def __init__(self, config=None):
        self.config = config or {}
        self.ti_config = self.config.get('threat_intel', {})
        self.virustotal_key = self.ti_config.get('virustotal_api_key', '')
        self.abuseipdb_key = self.ti_config.get('abuseipdb_api_key', '')
        self.cache = {}
        self.cache_ttl = 3600

    def check_virustotal(self, ip):
        """Check IP reputation on VirusTotal."""
        if not self.virustotal_key:
            return None

        cache_key = f'vt_{ip}'
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self.cache_ttl:
                return cached['data']

        try:
            headers = {'x-apikey': self.virustotal_key}
            resp = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers=headers,
                timeout=15
            )

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                result = {
                    'source': 'virustotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                    'is_malicious': stats.get('malicious', 0) > 3
                }
                self.cache[cache_key] = {'data': result, 'time': datetime.now()}
                return result
        except Exception:
            pass
        return None

    def check_abuseipdb(self, ip):
        """Check IP reputation on AbuseIPDB."""
        if not self.abuseipdb_key:
            return None

        cache_key = f'abd_{ip}'
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self.cache_ttl:
                return cached['data']

        try:
            headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
            resp = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                timeout=15
            )

            if resp.status_code == 200:
                data = resp.json().get('data', {})
                result = {
                    'source': 'abuseipdb',
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'country_code': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'usage_type': data.get('usageType', ''),
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50
                }
                self.cache[cache_key] = {'data': result, 'time': datetime.now()}
                return result
        except Exception:
            pass
        return None

    def check_threatcrowd(self, ip):
        """Check IP on ThreatCrowd (free, no API key)."""
        cache_key = f'tc_{ip}'
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self.cache_ttl:
                return cached['data']

        try:
            resp = requests.get(
                f'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}',
                timeout=10
            )

            if resp.status_code == 200:
                data = resp.json()
                result = {
                    'source': 'threatcrowd',
                    'resolutions': len(data.get('resolutions', [])),
                    'malicious_files': len(data.get('malicious_files', [])),
                    'references': len(data.get('references', [])),
                    'is_malicious': len(data.get('malicious_files', [])) > 0
                }
                self.cache[cache_key] = {'data': result, 'time': datetime.now()}
                return result
        except Exception:
            pass
        return None

    def full_check(self, ip):
        """Run all threat intelligence checks on an IP."""
        results = {
            'ip': ip,
            'checks': [],
            'is_malicious': False,
            'threat_score': 0,
            'timestamp': datetime.now().isoformat()
        }

        vt = self.check_virustotal(ip)
        if vt:
            results['checks'].append(vt)
            if vt.get('is_malicious'):
                results['is_malicious'] = True
                results['threat_score'] += vt.get('malicious', 0)

        abd = self.check_abuseipdb(ip)
        if abd:
            results['checks'].append(abd)
            if abd.get('is_malicious'):
                results['is_malicious'] = True
                results['threat_score'] += abd.get('abuse_confidence_score', 0) // 10

        tc = self.check_threatcrowd(ip)
        if tc:
            results['checks'].append(tc)
            if tc.get('is_malicious'):
                results['is_malicious'] = True
                results['threat_score'] += 10

        results['threat_score'] = min(results['threat_score'], 100)

        return results

    def format_alert(self, results):
        """Format threat intel results for alerts."""
        if not results.get('checks'):
            return None

        lines = ['Threat Intelligence Report:']

        if results.get('is_malicious'):
            lines.append(f"WARNING: IP flagged as malicious (score: {results.get('threat_score', 0)}/100)")

        for check in results.get('checks', []):
            source = check.get('source', 'unknown')
            if source == 'virustotal':
                lines.append(f"VirusTotal: {check.get('malicious', 0)} engines flagged malicious")
            elif source == 'abuseipdb':
                lines.append(f"AbuseIPDB: {check.get('abuse_confidence_score', 0)}% confidence, {check.get('total_reports', 0)} reports")
            elif source == 'threatcrowd':
                lines.append(f"ThreatCrowd: {check.get('malicious_files', 0)} malicious files associated")

        return '\n'.join(lines)
