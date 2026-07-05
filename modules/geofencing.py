"""WatchDog - Geofencing Module

Filters alerts based on geographic location.
Only alerts when triggered from unexpected locations.
"""

import os
import json
import requests


class Geofencer:
    """Manages geographic location-based alert filtering."""

    def __init__(self, config=None):
        self.config = config or {}
        self.geofence = self.config.get('geofencing', {})
        self.allowed_countries = self.geofence.get('allowed_countries', [])
        self.blocked_countries = self.geofence.get('blocked_countries', [])
        self.allowed_ips = self.geofence.get('allowed_ips', [])
        self.alert_on_unknown = self.geofence.get('alert_on_unknown_location', True)
        self._cache = {}

    def get_location(self, ip):
        """Get geolocation for an IP address."""
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
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as': data.get('as', '')
                }
                self._cache[ip] = location
                return location
        except Exception:
            pass
        return None

    def is_allowed(self, ip):
        """Check if an IP is within allowed geographic boundaries."""
        if ip in self.allowed_ips:
            return True, 'ip_whitelisted'

        location = self.get_location(ip)
        if not location:
            return self.alert_on_unknown, 'unknown_location'

        country_code = location.get('country_code', '')

        if self.blocked_countries and country_code in self.blocked_countries:
            return False, 'country_blocked'

        if self.allowed_countries and country_code not in self.allowed_countries:
            return False, 'country_not_allowed'

        return True, 'allowed'

    def is_vpn_or_proxy(self, ip):
        """Basic detection of VPN/proxy/Tor exit nodes."""
        location = self.get_location(ip)
        if not location:
            return False, 'unknown'

        suspicious_isps = [
            'tor', 'vpn', 'proxy', 'relays', 'exit',
            'nordvpn', 'expressvpn', 'surfshark', 'protonvpn',
            'mullvad', 'ivpn', 'private internet access',
            'hidemyass', 'cyberghost'
        ]

        isp_lower = location.get('isp', '').lower()
        org_lower = location.get('org', '').lower()

        for keyword in suspicious_isps:
            if keyword in isp_lower or keyword in org_lower:
                return True, location.get('isp', 'unknown')

        return False, 'clean'

    def evaluate(self, ip):
        """Full geofence evaluation for an IP."""
        allowed, reason = self.is_allowed(ip)
        is_vpn, vpn_provider = self.is_vpn_or_proxy(ip)

        return {
            'ip': ip,
            'allowed': allowed,
            'reason': reason,
            'is_vpn': is_vpn,
            'vpn_provider': vpn_provider if is_vpn else None,
            'location': self.get_location(ip),
            'should_alert': not allowed or is_vpn
        }

    def format_alert(self, evaluation):
        """Format geofence evaluation for alerts."""
        if not evaluation.get('should_alert'):
            return None

        location = evaluation.get('location', {})
        lines = [f"Geofence Alert: {evaluation.get('reason', 'unknown')}"]

        if evaluation.get('is_vpn'):
            lines.append(f"VPN/Proxy detected: {evaluation.get('vpn_provider')}")

        if location:
            lines.append(f"Location: {location.get('city', '?')}, {location.get('country', '?')}")
            lines.append(f"ISP: {location.get('isp', '?')}")

        return '\n'.join(lines)


class GeofenceConfig:
    """Helper to manage geofence configuration."""

    @staticmethod
    def create_config(allowed_countries=None, blocked_countries=None,
                      allowed_ips=None, alert_on_unknown=True):
        return {
            'allowed_countries': allowed_countries or [],
            'blocked_countries': blocked_countries or [],
            'allowed_ips': allowed_ips or [],
            'alert_on_unknown_location': alert_on_unknown
        }

    @staticmethod
    def from_file(path):
        with open(path, 'r') as f:
            return json.load(f)

    @staticmethod
    def to_file(config, path):
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)
