"""WatchDog - Notification Module"""

import time
from datetime import datetime
import requests


class Notifier:
    """Handles alerts via Discord and Telegram with rate limiting."""

    def __init__(self, config):
        self.config = config.get('notifications', {})
        self.rate_limit_minutes = config.get('rate_limit', 5)
        self.last_sent = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'WatchDog/1.0'})

    def _check_rate_limit(self, channel):
        now = time.time()
        last = self.last_sent.get(channel, 0)
        if (now - last) < (self.rate_limit_minutes * 60):
            return False
        return True

    def _update_last_sent(self, channel):
        self.last_sent[channel] = time.time()

    def send_alert(self, data):
        results = {}
        if self.config.get('discord', {}).get('enabled'):
            results['discord'] = self._send_discord(data)
        if self.config.get('telegram', {}).get('enabled'):
            results['telegram'] = self._send_telegram(data)
        return results

    def _send_discord(self, data):
        if not self._check_rate_limit('discord'):
            return {'status': 'rate_limited'}

        webhook_url = self.config.get('discord', {}).get('webhook_url')
        if not webhook_url:
            return {'status': 'no_webhook'}

        embed = self._build_discord_embed(data)
        payload = {'embeds': [embed]}

        try:
            response = self.session.post(webhook_url, json=payload, timeout=30)
            if response.status_code in (200, 204):
                self._update_last_sent('discord')
                return {'status': 'sent', 'channel': 'discord'}
            return {'status': 'failed', 'code': response.status_code}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _send_telegram(self, data):
        if not self._check_rate_limit('telegram'):
            return {'status': 'rate_limited'}

        bot_token = self.config.get('telegram', {}).get('bot_token')
        chat_id = self.config.get('telegram', {}).get('chat_id')

        if not bot_token or not chat_id:
            return {'status': 'no_config'}

        text = self._format_telegram_text(data)
        base_url = f"https://api.telegram.org/bot{bot_token}"

        try:
            response = self.session.post(
                f"{base_url}/sendMessage",
                json={'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'},
                timeout=30
            )
            if response.status_code == 200:
                self._update_last_sent('telegram')
                return {'status': 'sent', 'channel': 'telegram'}
            return {'status': 'failed', 'code': response.status_code}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _build_discord_embed(self, data):
        timestamp = data.get('timestamp', datetime.now().isoformat())
        embed = {
            'title': 'WatchDog Alert',
            'description': 'Canary file has been opened',
            'color': 0xFF6600,
            'timestamp': timestamp,
            'fields': []
        }

        field_map = {
            'hostname': 'Hostname',
            'username': 'Username',
            'public_ip': 'Public IP',
            'private_ip': 'Private IP',
            'os_system': 'OS',
            'os_release': 'OS Version',
            'wifi_ssid': 'WiFi Network',
            'wifi_bssid': 'WiFi BSSID',
            'geolocation': 'Geolocation',
            'mac_address': 'MAC Address'
        }

        for key, label in field_map.items():
            value = data.get(key)
            if value:
                embed['fields'].append({
                    'name': label,
                    'value': str(value)[:1024],
                    'inline': True
                })

        embed['footer'] = {'text': 'WatchDog Security Monitor'}
        return embed

    def _format_telegram_text(self, data):
        lines = ['WatchDog Alert', 'Canary file has been opened', '']
        field_map = {
            'hostname': 'Hostname',
            'username': 'Username',
            'public_ip': 'Public IP',
            'private_ip': 'Private IP',
            'os_system': 'OS',
            'os_release': 'OS Version',
            'wifi_ssid': 'WiFi Network',
            'wifi_bssid': 'WiFi BSSID',
            'geolocation': 'Geolocation',
            'mac_address': 'MAC Address'
        }
        for key, label in field_map.items():
            value = data.get(key)
            if value:
                lines.append(f'*{label}:* `{value}`')
        return '\n'.join(lines)

    def test_notification(self):
        test_data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': 'TEST_HOST',
            'username': 'test_user',
            'public_ip': '0.0.0.0',
            'os_system': 'Test OS',
            'message': 'WatchDog test notification'
        }
        return self.send_alert(test_data)
