"""WatchDog - System Intrusion Detection Tool

A legitimate security canary that alerts you when a file is opened.
Deploy on your own systems to detect unauthorized access.
"""

import os
import sys
import hashlib
import yaml
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.fingerprint import Fingerprinter
from modules.notifier import Notifier
from modules.crypto import Encryptor
from modules.logger import Logger
from modules.geofencing import Geofencer
from modules.threatintel import ThreatIntel
from modules.incidents import IncidentManager
from modules.process_monitor import ProcessMonitor
from modules.network_fingerprint import NetworkFingerprint
from modules.dns_canary import DNSCanary


ENV_OVERRIDES = {
    'WATCHDOG_DISCORD_WEBHOOK_URL': ('notifications', 'discord', 'webhook_url'),
    'WATCHDOG_TELEGRAM_BOT_TOKEN': ('notifications', 'telegram', 'bot_token'),
    'WATCHDOG_TELEGRAM_CHAT_ID': ('notifications', 'telegram', 'chat_id'),
    'WATCHDOG_SMTP_PASSWORD': ('smtp', 'password'),
    'WATCHDOG_ENCRYPTION_KEY': ('encryption', 'key'),
    'WATCHDOG_ABUSEIPDB_API_KEY': ('threat_intel', 'abuseipdb_api_key'),
    'WATCHDOG_VIRUSTOTAL_API_KEY': ('threat_intel', 'virustotal_api_key'),
}


def _set_nested(d, keys, value):
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')
    if not os.path.exists(config_path):
        print(f"Config not found: {config_path}")
        print("Copy config.example.yaml to config.yaml and fill in your settings.")
        print("Run 'python installer.py' to set up WatchDog.")
        sys.exit(1)
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f) or {}
    
    # Override sensitive values from environment variables
    for env_var, key_path in ENV_OVERRIDES.items():
        env_value = os.environ.get(env_var)
        if env_value:
            _set_nested(config, key_path, env_value)
    
    return config


def get_file_hash(file_path):
    if not os.path.exists(file_path):
        return None
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_file_integrity(config):
    integrity_config = config.get('integrity', {})
    if not integrity_config.get('enabled'):
        return None, None

    expected_hash = integrity_config.get('file_hash')
    canary_path = integrity_config.get('canary_path')

    if not expected_hash or not canary_path:
        return None, None

    current_hash = get_file_hash(canary_path)
    if current_hash is None:
        return None, None

    match = current_hash == expected_hash
    return current_hash, match


def run_sentinel():
    config = load_config()

    print("[*] Collecting system information...")
    fingerprinter = Fingerprinter()
    data = fingerprinter.collect_all()
    data['alert_type'] = 'canary_file_opened'
    data['tool'] = 'WatchDog'

    file_hash, hash_match = check_file_integrity(config)
    if file_hash:
        data['file_hash'] = file_hash
        data['hash_match'] = hash_match
        if not hash_match:
            print("[!] WARNING: File integrity check FAILED - file may have been tampered with")

    canary_name = config.get('integrity', {}).get('canary_name', 'unknown')
    data['canary_name'] = canary_name

    if config.get('process_monitor', {}).get('enabled', True):
        print("[*] Analyzing running processes...")
        proc_monitor = ProcessMonitor()
        proc_findings = proc_monitor.detect_suspicious()
        data['process_findings'] = {
            'hacking_tools': len(proc_findings.get('hacking_tools', [])),
            'analysis_tools': len(proc_findings.get('analysis_tools', [])),
            'suspicious_tools': len(proc_findings.get('suspicious_tools', [])),
            'suspicious_commands': len(proc_findings.get('suspicious_commands', []))
        }
        data['process_details'] = proc_monitor.format_findings(proc_findings)

        if proc_findings.get('hacking_tools') or proc_findings.get('analysis_tools'):
            print("[!] WARNING: Suspicious security tools detected on system!")

    if config.get('network_fingerprint', {}).get('enabled', True):
        print("[*] Analyzing network fingerprint...")
        net_fp = NetworkFingerprint(config)
        net_analysis = net_fp.analyze_network(data.get('public_ip', ''))
        data['network_fingerprint'] = net_analysis

        if net_analysis.get('is_suspicious'):
            print(f"[!] Suspicious network detected (threat score: {net_analysis.get('threat_score', 0)})")
        for finding in net_analysis.get('summary', []):
            print(f"    - {finding}")

    geofence_result = None
    if config.get('geofencing', {}).get('enabled'):
        print("[*] Checking geofence...")
        geofencer = Geofencer(config)
        geofence_result = geofencer.evaluate(data.get('public_ip', ''))
        data['geofence'] = geofence_result

        if geofence_result.get('is_vpn'):
            print("[!] VPN/Proxy detected!")
        if not geofence_result.get('allowed'):
            print("[!] Alert from blocked location!")

    threat_result = None
    if config.get('threat_intel', {}).get('enabled'):
        print("[*] Checking threat intelligence...")
        ti = ThreatIntel(config)
        threat_result = ti.full_check(data.get('public_ip', ''))
        data['threat_intel'] = threat_result

        if threat_result.get('is_malicious'):
            print("[!] IP flagged as malicious by threat intel!")

    encryption_config = config.get('encryption', {})
    if encryption_config.get('enabled'):
        print("[*] Encrypting alert data...")
        key = encryption_config.get('key', '')
        if not key:
            encryptor = Encryptor()
            key = encryptor.get_key()
            # Persist auto-generated key so encrypted alerts can be decrypted later
            key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.encryption_key')
            if not os.path.exists(key_path):
                encryptor.save_key(key_path)
                print(f"[+] Auto-generated encryption key saved to {key_path}")
        else:
            encryptor = Encryptor(key)
        
        # Collect sensitive PII fields to encrypt
        pii_fields = [
            'hostname', 'username', 'public_ip', 'private_ip', 'mac_address',
            'os_system', 'os_release', 'os_version', 'machine_type', 'processor',
            'wifi_ssid', 'wifi_bssid', 'wifi_signal', 'geolocation', 'geo_details',
            'installed_software_count', 'running_process_count'
        ]
        pii_data = {k: data.pop(k) for k in list(data.keys()) if k in pii_fields}
        pii_data['timestamp'] = data.get('timestamp', '')
        
        # Encrypt and replace plaintext with encrypted payload
        data['encrypted'] = True
        data['encrypted_payload'] = encryptor.encrypt_dict(pii_data)

    print("[*] Logging alert locally...")
    logger = Logger()
    alert_id = logger.log_alert(data, canary_name, file_hash, hash_match)
    print(f"[+] Alert logged with ID: {alert_id}")

    incident_manager = IncidentManager()
    incident_id = incident_manager.find_or_create_incident(data, alert_id)
    data['incident_id'] = incident_id
    print(f"[+] Incident: {incident_id}")

    should_send_alert = True
    if geofence_result and not geofence_result.get('should_alert') and not geofence_result.get('is_vpn'):
        if not threat_result or not threat_result.get('is_malicious'):
            net_fp_data = data.get('network_fingerprint', {})
            if not net_fp_data.get('is_suspicious'):
                print("[*] Alert suppressed by geofence (allowed location, no threat)")
                should_send_alert = False

    if should_send_alert:
        print("[*] Sending alert...")
        notifier = Notifier(config)
        results = notifier.send_alert(data)

        for channel, result in results.items():
            status = result.get('status', 'unknown')
            if status == 'sent':
                print(f"[+] Alert sent via {channel}")
            elif status == 'rate_limited':
                print(f"[!] Rate limited on {channel}")
            else:
                print(f"[-] Failed to send via {channel}: {result}")
    else:
        print("[*] Alert not sent (geofence allowed)")

    print("[*] Done.")


def run_dns_check():
    """Check all DNS canaries for changes."""
    config = load_config()
    dns_canary = DNSCanary(config)

    print("[*] Checking DNS canaries...")
    results = dns_canary.check_all_canaries()

    for result in results:
        if result.get('is_triggered'):
            print(f"[!] DNS CANARY TRIGGERED: {result.get('full_domain')}")
            print(f"    Expected: {result.get('expected_ip')}")
            print(f"    This indicates DNS hijacking!")

    if not results:
        print("[+] All DNS canaries OK")

    return results


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--dns-check':
        run_dns_check()
    else:
        run_sentinel()
