"""WatchDog - Setup Wizard"""

import os
import sys
import yaml


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    print(f"[+] Config saved to {CONFIG_PATH}")


def setup_discord(config):
    print("\n--- Discord Notifications ---")
    enabled = input("Enable Discord alerts? (y/n): ").strip().lower() == 'y'
    config.setdefault('notifications', {})['discord'] = {'enabled': enabled}
    if enabled:
        webhook = input("Discord webhook URL: ").strip()
        config['notifications']['discord']['webhook_url'] = webhook
    return config


def setup_telegram(config):
    print("\n--- Telegram Notifications ---")
    enabled = input("Enable Telegram alerts? (y/n): ").strip().lower() == 'y'
    config.setdefault('notifications', {})['telegram'] = {'enabled': enabled}
    if enabled:
        token = input("Telegram bot token: ").strip()
        chat_id = input("Telegram chat ID: ").strip()
        config['notifications']['telegram']['bot_token'] = token
        config['notifications']['telegram']['chat_id'] = chat_id
    return config


def setup_encryption(config):
    print("\n--- Encryption ---")
    enabled = input("Enable encryption for alert data? (y/n): ").strip().lower() == 'y'
    config.setdefault('encryption', {})['enabled'] = enabled
    if enabled:
        key = input("Encryption key (leave blank to auto-generate): ").strip()
        config['encryption']['key'] = key
    return config


def setup_rate_limit(config):
    print("\n--- Rate Limiting ---")
    minutes = input("Minutes between alerts (default 5): ").strip()
    config['rate_limit'] = int(minutes) if minutes.isdigit() else 5
    return config


def setup_logging(config):
    print("\n--- Local Logging ---")
    enabled = input("Enable local SQLite logging? (y/n): ").strip().lower() == 'y'
    config.setdefault('logging', {})['enabled'] = enabled
    return config


def setup_geofencing(config):
    print("\n--- Geofencing ---")
    enabled = input("Enable geofencing? (y/n): ").strip().lower() == 'y'
    config.setdefault('geofencing', {})['enabled'] = enabled
    if enabled:
        countries = input("Allowed countries (comma-separated ISO codes, e.g., US,CA,GB): ").strip()
        if countries:
            config['geofencing']['allowed_countries'] = [c.strip().upper() for c in countries.split(',')]
        else:
            config['geofencing']['allowed_countries'] = []

        blocked = input("Blocked countries (comma-separated, or leave blank): ").strip()
        if blocked:
            config['geofencing']['blocked_countries'] = [c.strip().upper() for c in blocked.split(',')]
        else:
            config['geofencing']['blocked_countries'] = []

        ips = input("Whitelisted IPs (comma-separated, or leave blank): ").strip()
        if ips:
            config['geofencing']['allowed_ips'] = [ip.strip() for ip in ips.split(',')]
        else:
            config['geofencing']['allowed_ips'] = []

        config['geofencing']['alert_on_unknown_location'] = True
    return config


def setup_threat_intel(config):
    print("\n--- Threat Intelligence ---")
    enabled = input("Enable threat intelligence checks? (y/n): ").strip().lower() == 'y'
    config.setdefault('threat_intel', {})['enabled'] = enabled
    if enabled:
        vt_key = input("VirusTotal API key (leave blank to skip): ").strip()
        abuse_key = input("AbuseIPDB API key (leave blank to skip): ").strip()
        config['threat_intel']['virustotal_api_key'] = vt_key
        config['threat_intel']['abuseipdb_api_key'] = abuse_key
    return config


def setup_process_monitor(config):
    print("\n--- Process Monitor ---")
    enabled = input("Enable suspicious process detection? (y/n, default y): ").strip().lower()
    config.setdefault('process_monitor', {})['enabled'] = enabled != 'n'
    return config


def setup_smtp(config):
    print("\n--- SMTP Email Reports ---")
    enabled = input("Enable email reports? (y/n): ").strip().lower() == 'y'
    config.setdefault('smtp', {})['enabled'] = enabled
    if enabled:
        config['smtp']['server'] = input("SMTP server (e.g., smtp.gmail.com): ").strip()
        config['smtp']['port'] = int(input("SMTP port (default 587): ").strip() or '587')
        config['smtp']['username'] = input("SMTP username/email: ").strip()
        config['smtp']['password'] = input("SMTP password: ").strip()
        config['smtp']['from_email'] = input("From email address: ").strip()
        to_emails = input("To email addresses (comma-separated): ").strip()
        config['smtp']['to_emails'] = [e.strip() for e in to_emails.split(',')]
    return config


def test_notifications(config):
    print("\n--- Test Notifications ---")
    test = input("Send test notification? (y/n): ").strip().lower() == 'y'
    if test:
        from modules.notifier import Notifier
        notifier = Notifier(config)
        results = notifier.test_notification()
        for channel, result in results.items():
            print(f"  {channel}: {result.get('status', 'unknown')}")


def view_alerts():
    print("\n--- View Local Alerts ---")
    view = input("View logged alerts? (y/n): ").strip().lower() == 'y'
    if view:
        from modules.logger import Logger
        logger = Logger()
        count = logger.get_alert_count()
        print(f"\nTotal alerts: {count}")
        if count > 0:
            alerts = logger.get_alerts(limit=10)
            print("\nRecent alerts:")
            for alert in alerts:
                print(f"  [{alert['id']}] {alert['timestamp']} - {alert['username']}@{alert['hostname']} ({alert['public_ip']})")


def view_incidents():
    print("\n--- View Incidents ---")
    view = input("View open incidents? (y/n): ").strip().lower() == 'y'
    if view:
        from modules.incidents import IncidentManager
        im = IncidentManager()
        stats = im.get_incident_stats()
        print(f"\nOpen: {stats['open']} | Critical: {stats['critical']} | High: {stats['high']}")

        incidents = im.get_open_incidents(limit=5)
        if incidents:
            for inc in incidents:
                print(f"  {inc['incident_id']} - {inc['title']} [{inc['severity']}]")


def manage_honeytokens():
    print("\n--- Honeytoken Management ---")
    action = input("Action (create/list/exit): ").strip().lower()
    if action == 'exit':
        return

    from modules.honeytokens import HoneytokenManager
    hm = HoneytokenManager()

    if action == 'create':
        token_type = input("Token type (aws_key/password/api_key/database/crypto_wallet/credit_card): ").strip()
        name = input("Token name: ").strip()
        desc = input("Description (optional): ").strip()
        token = hm.generate_token(token_type, name, desc)
        print(f"\n[+] Token created: {token['id']}")
        if 'access_key' in token:
            print(f"    Access Key: {token['access_key']}")
            print(f"    Secret Key: {token['secret_key']}")
        elif 'username' in token:
            print(f"    Username: {token['username']}")
            print(f"    Password: {token['password']}")
        elif 'api_key' in token:
            print(f"    API Key: {token['api_key']}")

    elif action == 'list':
        tokens = hm.get_all_tokens(active_only=False)
        if tokens:
            for tid, t in tokens.items():
                status = "ACTIVE" if t.get('is_active') else "INACTIVE"
                triggered = t.get('trigger_count', 0)
                print(f"  [{status}] {t['name']} ({t['type']}) - {triggered} triggers")
        else:
            print("  No tokens configured")


def main():
    print("=" * 50)
    print("  WatchDog Setup Wizard")
    print("=" * 50)

    config = load_config()

    config = setup_discord(config)
    config = setup_telegram(config)
    config = setup_encryption(config)
    config = setup_rate_limit(config)
    config = setup_logging(config)
    config = setup_geofencing(config)
    config = setup_threat_intel(config)
    config = setup_process_monitor(config)
    config = setup_smtp(config)

    save_config(config)
    test_notifications(config)
    view_alerts()
    view_incidents()
    manage_honeytokens()

    print("\n[+] Setup complete!")
    print("    Run 'python build/build.py --name canary_file --decoy passwords' to create a canary.")
    print("    Place the generated file where you want to detect access.")


if __name__ == '__main__':
    main()
