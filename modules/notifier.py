"""WatchDog - Notification Module"""

import os
import time
from datetime import datetime
import requests


class Notifier:
    """Handles alerts via Discord and Telegram with rate limiting and fallback."""

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

    DISCORD_WEBHOOK_PATTERN = r'^https://discord\.com/api/webhooks/\d+/[\w\-]+$'
    TELEGRAM_API_PATTERN = r'^https://api\.telegram\.org/bot[\w:]+$'

    def _validate_url(self, url, pattern):
        """Validate URL matches expected pattern to prevent SSRF."""
        import re
        if not url:
            return False
        return bool(re.match(pattern, url))

    def verify_webhook(self, webhook_url):
        """
        Verify a Discord webhook is still valid by fetching its metadata.
        Returns True if the webhook exists and is usable.
        """
        if not webhook_url:
            return False
        if not self._validate_url(webhook_url, self.DISCORD_WEBHOOK_PATTERN):
            return False
        try:
            resp = self.session.get(webhook_url, timeout=10, verify=True)
            if resp.status_code == 200:
                data = resp.json()
                return bool(data.get('id') and data.get('token'))
            return False
        except Exception:
            return False

    def send_alert(self, data):
        results = {}
        fallback_data = None

        if self.config.get('discord', {}).get('enabled'):
            results['discord'] = self._send_discord(data)
            if results['discord'].get('status') != 'sent':
                fallback_data = data

        if self.config.get('telegram', {}).get('enabled'):
            results['telegram'] = self._send_telegram(data)
            if results['telegram'].get('status') != 'sent' and fallback_data is None:
                fallback_data = data

        # Multi-channel fallback: if all enabled channels failed, try any remaining
        if fallback_data is not None:
            sent_count = sum(1 for r in results.values() if r.get('status') == 'sent')
            if sent_count == 0:
                for channel_name, send_fn in [
                    ('discord', self._send_discord),
                    ('telegram', self._send_telegram),
                ]:
                    if channel_name not in results and self.config.get(channel_name, {}).get('enabled'):
                        results[channel_name] = send_fn(data)
                        if results[channel_name].get('status') == 'sent':
                            break

        return results

    def _send_discord(self, data):
        if not self._check_rate_limit('discord'):
            return {'status': 'rate_limited'}

        webhook_url = self.config.get('discord', {}).get('webhook_url')
        if not webhook_url:
            return {'status': 'no_webhook'}

        # Verify webhook is still valid before sending
        if not self.verify_webhook(webhook_url):
            return {'status': 'webhook_dead', 'message': 'Webhook no longer exists or is invalid'}

        embed = self._build_discord_embed(data)
        payload = {'embeds': [embed]}

        try:
            response = self.session.post(webhook_url, json=payload, timeout=30)
            if response.status_code in (200, 204):
                self._update_last_sent('discord')
                return {'status': 'sent', 'channel': 'discord'}
            elif response.status_code in (401, 404):
                return {'status': 'webhook_dead', 'code': response.status_code}
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

        if data.get('encrypted'):
            embed['fields'].append({
                'name': 'Notice',
                'value': 'Alert data is encrypted. Decrypt with the encryption key.',
                'inline': False
            })
            enc_payload = data.get('encrypted_payload', '')
            if enc_payload:
                embed['fields'].append({
                    'name': 'Encrypted Payload',
                    'value': f'`{str(enc_payload)[:1024]}`',
                    'inline': False
                })
        else:
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
        
        if data.get('encrypted'):
            lines.append('_Alert data is encrypted. Decrypt with the encryption key._')
            enc_payload = data.get('encrypted_payload', '')
            if enc_payload:
                lines.append(f'`{str(enc_payload)[:500]}`')
        else:
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
