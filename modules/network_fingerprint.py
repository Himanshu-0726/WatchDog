"""WatchDog - Network Fingerprinting Module

Identifies VPN, proxy, Tor exit nodes, and other network anomalies.
Provides detailed network analysis for threat assessment.
"""

import socket
import requests
from datetime import datetime


class NetworkFingerprint:
    """Comprehensive network analysis and identification."""

    def __init__(self, config=None):
        self.config = config or {}
        self.nf_config = self.config.get('network_fingerprint', {})
        self._cache = {}
        self.cache_ttl = 3600

    def detect_vpn(self, ip):
        """Detect if IP belongs to a known VPN provider."""
        vpn_providers = {
            'commercial': [
                'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'mullvad',
                'ivpn', 'private internet access', 'pia', 'cyberghost',
                'hidemyass', 'hma', 'tunnelbear', 'windscribe', 'vyprvpn',
                'hotspot shield', 'ipvanish', 'purevpn', 'zenmate',
                'unlocator', 'smartdns', 'getflix', 'unblock-us'
            ],
            'corporate': [
                'zscaler', 'paloalto', 'globalprotect', 'cisco anyconnect',
                'fortinet', 'fortigate', 'sophos', 'checkpoint',
                'pulse secure', 'juniper', 'citrix', 'netMotion'
            ],
            'free': [
                'protonvpn free', 'windscribe free', 'tunnelbear free',
                'hotspot shield free', 'vpnbook', 'vpnproxy'
            ]
        }

        location = self._get_location(ip)
        if not location:
            return {'is_vpn': False, 'confidence': 0}

        isp = location.get('isp', '').lower()
        org = location.get('org', '').lower()

        for category, providers in vpn_providers.items():
            for provider in providers:
                if provider.lower() in isp or provider.lower() in org:
                    return {
                        'is_vpn': True,
                        'provider': provider,
                        'category': category,
                        'confidence': 95,
                        'isp': location.get('isp'),
                        'org': location.get('org')
                    }

        return {'is_vpn': False, 'confidence': 0}

    def detect_proxy(self, ip):
        """Detect if IP is a known proxy server."""
        proxy_indicators = [
            'proxy', 'proxifier', 'anonymizer', 'anonymous',
            'hide my', 'unblock', 'access private'
        ]

        location = self._get_location(ip)
        if not location:
            return {'is_proxy': False}

        isp = location.get('isp', '').lower()
        org = location.get('org', '').lower()

        for indicator in proxy_indicators:
            if indicator in isp or indicator in org:
                return {
                    'is_proxy': True,
                    'type': 'web_proxy',
                    'isp': location.get('isp'),
                    'confidence': 80
                }

        return {'is_proxy': False, 'confidence': 0}

    def detect_tor(self, ip):
        """Check if IP is a known Tor exit node."""
        try:
            resp = requests.get(
                f'https://check.torproject.org/torbulkexitlist',
                timeout=10
            )
            if resp.status_code == 200:
                tor_ips = set(resp.text.strip().split('\n'))
                if ip in tor_ips:
                    return {
                        'is_tor': True,
                        'confidence': 100,
                        'note': 'IP is a known Tor exit node'
                    }
        except Exception:
            pass

        return {'is_tor': False, 'confidence': 0}

    def detect_cloud_provider(self, ip):
        """Detect if IP belongs to a cloud provider."""
        cloud_ranges = {
            'aws': ['amazon', 'aws'],
            'azure': ['microsoft', 'azure'],
            'gcp': ['google', 'gcp'],
            'cloudflare': ['cloudflare'],
            'akamai': ['akamai', 'limelight'],
            'fastly': ['fastly'],
            'cloudfront': ['cloudfront']
        }

        location = self._get_location(ip)
        if not location:
            return {'is_cloud': False}

        org = location.get('org', '').lower()
        isp = location.get('isp', '').lower()

        for provider, keywords in cloud_ranges.items():
            for keyword in keywords:
                if keyword in org or keyword in isp:
                    return {
                        'is_cloud': True,
                        'provider': provider,
                        'org': location.get('org'),
                        'confidence': 90
                    }

        return {'is_cloud': False, 'confidence': 0}

    def detect_datacenter(self, ip):
        """Detect if IP belongs to a datacenter/hosting provider."""
        dc_indicators = [
            'hosting', 'datacenter', 'data center', 'colocation',
            'server', 'dedicated', 'vps', 'virtual private',
            'cloud server', 'bare metal', 'colo'
        ]

        location = self._get_location(ip)
        if not location:
            return {'is_datacenter': False}

        org = location.get('org', '').lower()
        isp = location.get('isp', '').lower()

        for indicator in dc_indicators:
            if indicator in org or indicator in isp:
                return {
                    'is_datacenter': True,
                    'provider': location.get('isp'),
                    'confidence': 85
                }

        return {'is_datacenter': False, 'confidence': 0}

    def detect_residential(self, ip):
        """Check if IP appears to be residential."""
        non_residential = ['vpn', 'proxy', 'hosting', 'server', 'cloud', 'datacenter']

        location = self._get_location(ip)
        if not location:
            return {'is_residential': 'unknown'}

        org = location.get('org', '').lower()
        isp = location.get('isp', '').lower()

        for indicator in non_residential:
            if indicator in org or indicator in isp:
                return {'is_residential': False, 'reason': indicator}

        return {'is_residential': True, 'confidence': 70}

    def analyze_network(self, ip):
        """Full network analysis for an IP."""
        vpn = self.detect_vpn(ip)
        proxy = self.detect_proxy(ip)
        tor = self.detect_tor(ip)
        cloud = self.detect_cloud_provider(ip)
        dc = self.detect_datacenter(ip)
        residential = self.detect_residential(ip)

        threat_score = 0
        if vpn.get('is_vpn'):
            threat_score += 30
        if proxy.get('is_proxy'):
            threat_score += 40
        if tor.get('is_tor'):
            threat_score += 60
        if dc.get('is_datacenter'):
            threat_score += 20

        return {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'vpn': vpn,
            'proxy': proxy,
            'tor': tor,
            'cloud': cloud,
            'datacenter': dc,
            'residential': residential,
            'threat_score': min(threat_score, 100),
            'is_suspicious': threat_score > 50,
            'summary': self._generate_summary(vpn, proxy, tor, cloud, dc)
        }

    def _get_location(self, ip):
        if ip in self._cache:
            return self._cache[ip]

        try:
            resp = requests.get(f'https://ip-api.com/json/{ip}', timeout=10)
            data = resp.json()
            if data.get('status') == 'success':
                location = {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as': data.get('as', '')
                }
                self._cache[ip] = location
                return location
        except Exception:
            pass
        return None

    def _generate_summary(self, vpn, proxy, tor, cloud, dc):
        findings = []
        if vpn.get('is_vpn'):
            findings.append(f"VPN: {vpn.get('provider', 'Unknown')} ({vpn.get('category', 'unknown')})")
        if proxy.get('is_proxy'):
            findings.append(f"Proxy: {proxy.get('type', 'Unknown')}")
        if tor.get('is_tor'):
            findings.append("Tor Exit Node")
        if cloud.get('is_cloud'):
            findings.append(f"Cloud: {cloud.get('provider', 'Unknown')}")
        if dc.get('is_datacenter'):
            findings.append(f"Datacenter: {dc.get('provider', 'Unknown')}")

        return findings if findings else ['Clean - likely residential']

    def format_alert(self, analysis):
        """Format network analysis for alerts."""
        lines = ['Network Fingerprint Analysis:']

        if analysis.get('is_suspicious'):
            lines.append(f"THREAT SCORE: {analysis.get('threat_score', 0)}/100")

        for finding in analysis.get('summary', []):
            lines.append(f"  - {finding}")

        if analysis.get('vpn', {}).get('is_vpn'):
            lines.append(f"  VPN Provider: {analysis['vpn'].get('provider')}")
            lines.append(f"  VPN Category: {analysis['vpn'].get('category')}")

        return '\n'.join(lines)


class NetworkFingerprintConfig:
    """Helper to manage network fingerprint configuration."""

    @staticmethod
    def create_config(detect_vpn=True, detect_proxy=True, detect_tor=True,
                      detect_cloud=True, detect_datacenter=True):
        return {
            'detect_vpn': detect_vpn,
            'detect_proxy': detect_proxy,
            'detect_tor': detect_tor,
            'detect_cloud': detect_cloud,
            'detect_datacenter': detect_datacenter
        }
