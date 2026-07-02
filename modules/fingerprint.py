"""WatchDog - System Fingerprinting Module"""

import os
import sys
import socket
import uuid
import platform
import subprocess
import json
from datetime import datetime


class Fingerprinter:
    """Collects system information, WiFi data, and geolocation."""

    def __init__(self):
        self._requests = None

    def _load_requests(self):
        if self._requests is None:
            import requests
            self._requests = requests
        return self._requests

    def hostname(self):
        return socket.gethostname()

    def username(self):
        return os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))

    def public_ip(self):
        try:
            r = self._load_requests()
            resp = r.get('https://api.ipify.org', timeout=10)
            return resp.text.strip()
        except Exception:
            return 'unknown'

    def private_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return 'unknown'

    def mac_address(self):
        mac = uuid.getnode()
        return ':'.join(f'{(mac >> i) & 0xFF:02x}' for i in range(0, 48, 8))

    def os_info(self):
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }

    def geolocation(self, ip=None):
        if ip is None:
            ip = self.public_ip()
        if ip == 'unknown':
            return {}

        try:
            r = self._load_requests()
            resp = r.get(f'http://ip-api.com/json/{ip}', timeout=10)
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as')
                }
        except Exception:
            pass
        return {}

    def wifi_info(self):
        if sys.platform == 'win32':
            return self._wifi_windows()
        elif sys.platform == 'darwin':
            return self._wifi_mac()
        else:
            return self._wifi_linux()

    def _wifi_windows(self):
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            info = {}
            for line in output.split('\n'):
                line = line.strip()
                if 'SSID' in line and 'BSSID' not in line:
                    info['ssid'] = line.split(':', 1)[-1].strip()
                elif 'BSSID' in line:
                    info['bssid'] = line.split(':', 1)[-1].strip()
                elif 'Signal' in line:
                    info['signal'] = line.split(':', 1)[-1].strip()
                elif 'Authentication' in line:
                    info['auth'] = line.split(':', 1)[-1].strip()
                elif 'Channel' in line:
                    info['channel'] = line.split(':', 1)[-1].strip()
            return info
        except Exception:
            return {}

    def _wifi_linux(self):
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'active,ssid,bssid,freq,signal', 'dev', 'wifi'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split('\n'):
                if line.startswith('yes:'):
                    parts = line.split(':')
                    return {
                        'ssid': parts[1] if len(parts) > 1 else 'unknown',
                        'bssid': parts[2] if len(parts) > 2 else 'unknown',
                        'frequency': parts[3] if len(parts) > 3 else 'unknown',
                        'signal': parts[4] if len(parts) > 4 else 'unknown'
                    }
        except Exception:
            pass
        try:
            result = subprocess.run(
                ['iwconfig'], capture_output=True, text=True, timeout=10
            )
            info = {}
            for line in result.stdout.split('\n'):
                if 'ESSID' in line:
                    info['ssid'] = line.split('"')[1] if '"' in line else 'unknown'
                elif 'Access Point' in line:
                    info['bssid'] = line.split(':', 1)[-1].strip()
            return info
        except Exception:
            return {}

    def _wifi_mac(self):
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                capture_output=True, text=True, timeout=10
            )
            info = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ' SSID:' in line:
                    info['ssid'] = line.split(':', 1)[-1].strip()
                elif ' BSSID:' in line:
                    info['bssid'] = line.split(':', 1)[-1].strip()
                elif ' channel:' in line:
                    info['channel'] = line.split(':', 1)[-1].strip()
            return info
        except Exception:
            return {}

    def installed_software(self):
        software = []
        if sys.platform == 'win32':
            software = self._software_windows()
        elif sys.platform == 'darwin':
            software = self._software_mac()
        else:
            software = self._software_linux()
        return software[:100]

    def _software_windows(self):
        software = []
        try:
            import winreg
            hives = [
                (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            ]
            for hive, subkey in hives:
                try:
                    key = winreg.OpenKey(hive, subkey)
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey_handle = winreg.OpenKey(key, subkey_name)
                            try:
                                name = winreg.QueryValueEx(subkey_handle, 'DisplayName')[0]
                                software.append(name)
                            except FileNotFoundError:
                                pass
                            winreg.CloseKey(subkey_handle)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    continue
        except Exception:
            pass
        return sorted(set(software))

    def _software_linux(self):
        software = []
        try:
            result = subprocess.run(['dpkg', '--get-selections'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\n'):
                if '\tinstall' in line:
                    software.append(line.split('\t')[0])
        except Exception:
            try:
                result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True, timeout=10)
                software = result.stdout.strip().split('\n')
            except Exception:
                pass
        return sorted(set(software))

    def _software_mac(self):
        software = []
        try:
            result = subprocess.run(['ls', '/Applications'], capture_output=True, text=True, timeout=10)
            software = [d.replace('.app', '') for d in result.stdout.strip().split('\n') if d.endswith('.app')]
        except Exception:
            pass
        return sorted(software)

    def running_processes(self):
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return processes[:200]
        except ImportError:
            return []

    def collect_all(self):
        ip = self.public_ip()
        geo = self.geolocation(ip)
        geo_str = ''
        if geo:
            parts = [geo.get('city'), geo.get('region'), geo.get('country')]
            geo_str = ', '.join(p for p in parts if p)

        return {
            'hostname': self.hostname(),
            'username': self.username(),
            'public_ip': ip,
            'private_ip': self.private_ip(),
            'mac_address': self.mac_address(),
            'os_system': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'machine_type': platform.machine(),
            'processor': platform.processor(),
            'wifi_ssid': self.wifi_info().get('ssid', 'unknown'),
            'wifi_bssid': self.wifi_info().get('bssid', 'unknown'),
            'wifi_signal': self.wifi_info().get('signal', 'unknown'),
            'geolocation': geo_str,
            'geo_details': geo,
            'installed_software_count': len(self.installed_software()),
            'running_process_count': len(self.running_processes()),
            'timestamp': datetime.now().isoformat()
        }
