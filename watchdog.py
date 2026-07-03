"""WatchDog - Simple Setup & Deployment

One command to set up and deploy security canaries.

Usage:
    python watchdog.py setup          # Configure notifications
    python watchdog.py deploy         # Create and deploy canary
    python watchdog.py test           # Send test alert
    python watchdog.py status         # Check alerts and config
"""

import os
import sys
import shutil
import argparse
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.yaml')
BUILD_DIR = os.path.join(SCRIPT_DIR, 'build')


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}


def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)


def print_banner():
    print("=" * 50)
    print("  WatchDog - Security Canary Tool")
    print("=" * 50)


def cmd_setup(args):
    """Interactive setup - only asks for what you need."""
    print_banner()
    print("  Quick Setup\n")

    config = load_config()
    config.setdefault('notifications', {})
    config.setdefault('logging', {'enabled': True})
    config.setdefault('process_monitor', {'enabled': True})
    config.setdefault('rate_limit', 5)

    print("How do you want to be alerted?\n")
    print("  1. Discord (Recommended)")
    print("  2. Telegram")
    print("  3. Both")
    print("  4. Skip (local logging only)\n")

    choice = input("Choice [1]: ").strip() or '1'

    if choice in ('1', '3'):
        print("\n--- Discord Setup ---")
        print("To create a webhook:")
        print("  1. Open Discord > Server Settings > Integrations > Webhooks")
        print("  2. Click 'New Webhook', copy the URL\n")
        webhook = input("Paste Discord webhook URL: ").strip()
        if webhook:
            config['notifications']['discord'] = {
                'enabled': True,
                'webhook_url': webhook
            }
            print("[+] Discord configured")
        else:
            print("[-] Skipped Discord")

    if choice in ('2', '3'):
        print("\n--- Telegram Setup ---")
        print("To create a bot:")
        print("  1. Message @BotFather on Telegram")
        print("  2. Send /newbot and follow instructions")
        print("  3. Copy the bot token")
        print("  4. Message your bot, then visit:")
        print("     https://api.telegram.org/bot<TOKEN>/getUpdates\n")
        token = input("Paste bot token: ").strip()
        chat_id = input("Paste chat ID: ").strip()
        if token and chat_id:
            config['notifications']['telegram'] = {
                'enabled': True,
                'bot_token': token,
                'chat_id': chat_id
            }
            print("[+] Telegram configured")
        else:
            print("[-] Skipped Telegram")

    if not config['notifications'].get('discord', {}).get('enabled') and \
       not config['notifications'].get('telegram', {}).get('enabled'):
        print("\n[!] No notification channel configured.")
        print("    Alerts will be logged locally only.\n")

    save_config(config)
    print("\n[+] Setup complete!")
    print("    Run 'python watchdog.py deploy' to create your first canary.")


def cmd_deploy(args):
    """Build and deploy a canary file."""
    print_banner()

    config = load_config()

    has_notification = (
        config.get('notifications', {}).get('discord', {}).get('enabled') or
        config.get('notifications', {}).get('telegram', {}).get('enabled')
    )
    if not has_notification:
        print("[!] No notification channel configured.")
        print("    Run 'python watchdog.py setup' first, or alerts won't be sent.\n")

    name = args.name or 'passwords'
    decoy = args.decoy or 'passwords'
    location = args.location

    print(f"[*] Building canary: {name}")
    sys.path.insert(0, SCRIPT_DIR)
    from build.build import build_bat, build_decoy, save_integrity_config, get_file_hash

    canary_path = build_bat(name)
    build_decoy(name, decoy)

    integrity_hash = get_file_hash(canary_path)
    integrity_config = config.get('integrity', {})
    integrity_config['enabled'] = True
    integrity_config['file_hash'] = integrity_hash
    integrity_config['canary_name'] = name
    integrity_config['canary_path'] = canary_path
    config['integrity'] = integrity_config
    save_config(config)

    print(f"[+] Canary created: {canary_path}")

    if location:
        dest = resolve_destination(name, location)
        if dest:
            shutil.copy2(canary_path, dest)
            print(f"[+] Deployed to: {dest}")
        else:
            print(f"[-] Unknown location: {location}")
            print("    Use: desktop, documents, downloads, or a full path")
            return
    else:
        print(f"\n    To deploy, copy the file manually:")
        print(f"    copy \"{canary_path}\" \"%USERPROFILE%\\Desktop\\{name}.bat\"")
        print(f"\n    Or run: python watchdog.py deploy --location desktop")

    print("\n[+] When someone opens the file, you'll get an alert!")


def resolve_destination(name, location):
    """Resolve deployment location to a full path."""
    home = os.path.expanduser("~")
    locations = {
        'desktop': [
            os.path.join(home, 'OneDrive', 'Desktop'),
            os.path.join(home, 'Desktop'),
        ],
        'documents': [
            os.path.join(home, 'OneDrive', 'Documents'),
            os.path.join(home, 'Documents'),
        ],
        'downloads': [
            os.path.join(home, 'OneDrive', 'Downloads'),
            os.path.join(home, 'Downloads'),
        ],
    }

    if location.lower() in locations:
        for dest_dir in locations[location.lower()]:
            if os.path.exists(dest_dir):
                return os.path.join(dest_dir, f'{name}.bat')
        return os.path.join(locations[location.lower()][0], f'{name}.bat')
    elif os.path.isabs(location):
        return os.path.join(location, f'{name}.bat')
    elif os.path.isdir(location):
        return os.path.join(os.path.abspath(location), f'{name}.bat')
    else:
        return None


def cmd_test(args):
    """Send a test notification."""
    print_banner()

    config = load_config()
    has_notification = (
        config.get('notifications', {}).get('discord', {}).get('enabled') or
        config.get('notifications', {}).get('telegram', {}).get('enabled')
    )
    if not has_notification:
        print("[-] No notification channel configured.")
        print("    Run 'python watchdog.py setup' first.")
        return

    print("[*] Sending test notification...")
    sys.path.insert(0, SCRIPT_DIR)
    from modules.notifier import Notifier

    notifier = Notifier(config)
    results = notifier.test_notification()

    for channel, result in results.items():
        status = result.get('status', 'unknown')
        if status == 'sent':
            print(f"[+] {channel}: Test alert sent!")
        else:
            print(f"[-] {channel}: {status}")


def cmd_status(args):
    """Show current status and recent alerts."""
    print_banner()

    config = load_config()

    print("Configuration:")
    discord_enabled = config.get('notifications', {}).get('discord', {}).get('enabled', False)
    telegram_enabled = config.get('notifications', {}).get('telegram', {}).get('enabled', False)
    print(f"  Discord:   {'Enabled' if discord_enabled else 'Disabled'}")
    print(f"  Telegram:  {'Enabled' if telegram_enabled else 'Disabled'}")
    print(f"  Logging:   {'Enabled' if config.get('logging', {}).get('enabled', True) else 'Disabled'}")

    canary_name = config.get('integrity', {}).get('canary_name', 'None')
    print(f"  Canary:    {canary_name}")

    print("\nRecent Alerts:")
    sys.path.insert(0, SCRIPT_DIR)
    from modules.logger import Logger
    logger = Logger()
    count = logger.get_alert_count()
    print(f"  Total: {count}")

    if count > 0:
        alerts = logger.get_alerts(limit=5)
        for alert in alerts:
            print(f"  [{alert['id']}] {alert['timestamp']} - {alert['username']}@{alert['hostname']} ({alert['public_ip']})")


def cmd_advanced(args):
    """Launch the full setup wizard for advanced options."""
    print_banner()
    print("  Launching advanced setup wizard...\n")
    sys.path.insert(0, SCRIPT_DIR)
    import installer
    installer.main()


def main():
    parser = argparse.ArgumentParser(
        description='WatchDog - Security Canary Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python watchdog.py setup                     Quick setup
  python watchdog.py deploy                    Create canary file
  python watchdog.py deploy --name api_keys    Create named canary
  python watchdog.py deploy --location desktop Create and deploy to desktop
  python watchdog.py test                      Send test alert
  python watchdog.py status                    View alerts
  python watchdog.py advanced                  Full setup wizard
        """
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    subparsers.add_parser('setup', help='Quick setup (configure notifications)')
    subparsers.add_parser('test', help='Send test notification')

    deploy_parser = subparsers.add_parser('deploy', help='Build and deploy canary')
    deploy_parser.add_argument('--name', default='passwords', help='Canary filename (default: passwords)')
    deploy_parser.add_argument('--decoy', default='passwords',
                               choices=['passwords', 'financial', 'credentials', 'crypto', 'personal', 'documents'],
                               help='Decoy content type (default: passwords)')
    deploy_parser.add_argument('--location', help='Deploy to: desktop, documents, downloads, or full path')

    subparsers.add_parser('status', help='View config and recent alerts')
    subparsers.add_parser('advanced', help='Open full setup wizard')

    args = parser.parse_args()

    if args.command == 'setup':
        cmd_setup(args)
    elif args.command == 'deploy':
        cmd_deploy(args)
    elif args.command == 'test':
        cmd_test(args)
    elif args.command == 'status':
        cmd_status(args)
    elif args.command == 'advanced':
        cmd_advanced(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
