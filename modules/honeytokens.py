"""WatchDog - Honeytoken Module

Creates and manages credential honeytokens - fake credentials that
alert when used, helping detect credential theft and lateral movement.
"""

import os
import json
import random
import secrets
import string
from datetime import datetime


class HoneytokenManager:
    """Manages credential honeytokens across multiple platforms."""

    def __init__(self, config=None):
        self.config = config or {}
        self.honeytoken_config = self.config.get('honeytokens', {})
        self.tokens = {}
        self._load_tokens()

    def _tokens_path(self):
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'honeytokens.json')

    def _load_tokens(self):
        path = self._tokens_path()
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.tokens = json.load(f)

    def _save_tokens(self):
        with open(self._tokens_path(), 'w') as f:
            json.dump(self.tokens, f, indent=2)

    def generate_token(self, token_type, name, description=''):
        """Generate a new honeytoken."""
        token_id = f"{token_type}_{secrets.token_hex(8)}"
        created_at = datetime.now().isoformat()

        token_data = {
            'id': token_id,
            'type': token_type,
            'name': name,
            'description': description,
            'created_at': created_at,
            'last_triggered': None,
            'trigger_count': 0,
            'is_active': True
        }

        if token_type == 'aws_key':
            # FAKE KEY: This is a honeytoken for authorized security monitoring only
            token_data['access_key'] = f"FAKE{secrets.token_hex(10).upper()}"
            token_data['secret_key'] = secrets.token_urlsafe(30)

        elif token_type == 'password':
            token_data['username'] = f"admin_{secrets.token_hex(4)}"
            token_data['password'] = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%') for _ in range(16))

        elif token_type == 'api_key':
            token_data['api_key'] = secrets.token_hex(32)
            token_data['api_secret'] = secrets.token_hex(32)

        elif token_type == 'database':
            token_data['connection_string'] = f"mysql://honey_{secrets.token_hex(4)}:db_{secrets.token_hex(8)}@localhost:3306/production"

        elif token_type == 'ssh_key':
            token_data['username'] = f"deploy_{secrets.token_hex(4)}"
            token_data['comment'] = f"Deploy key - {name}"

        elif token_type == 'credit_card':
            # FAKE CARD: This is a honeytoken for authorized security monitoring only
            token_data['number'] = f"XXXX-XXXX-XXXX-{random.randint(1000,9999)}"
            token_data['expiry'] = f"12/2028"
            token_data['cvv'] = f"{random.randint(100,999)}"

        elif token_type == 'crypto_wallet':
            token_data['address'] = f"0x{''.join(secrets.choice('0123456789abcdef') for _ in range(40))}"
            token_data['label'] = f"Honey wallet - {name}"

        self.tokens[token_id] = token_data
        self._save_tokens()

        return token_data

    def trigger_token(self, token_id, trigger_info=None):
        """Record that a honeytoken was triggered."""
        if token_id not in self.tokens:
            return False

        self.tokens[token_id]['last_triggered'] = datetime.now().isoformat()
        self.tokens[token_id]['trigger_count'] += 1

        if trigger_info is None:
            trigger_info = {}

        if 'triggers' not in self.tokens[token_id]:
            self.tokens[token_id]['triggers'] = []

        self.tokens[token_id]['triggers'].append({
            'timestamp': datetime.now().isoformat(),
            **trigger_info
        })

        self._save_tokens()
        return True

    def get_token(self, token_id):
        return self.tokens.get(token_id)

    def get_all_tokens(self, active_only=True):
        if active_only:
            return {k: v for k, v in self.tokens.items() if v.get('is_active')}
        return self.tokens

    def deactivate_token(self, token_id):
        if token_id in self.tokens:
            self.tokens[token_id]['is_active'] = False
            self._save_tokens()
            return True
        return False

    def delete_token(self, token_id):
        if token_id in self.tokens:
            del self.tokens[token_id]
            self._save_tokens()
            return True
        return False

    def get_triggered_tokens(self):
        return {k: v for k, v in self.tokens.items() if v.get('trigger_count', 0) > 0}

    def format_for_ad(self, token):
        """Format token for Active Directory deployment."""
        if token['type'] == 'password':
            return {
                'username': token['username'],
                'password': token['password'],
                'description': f"Honeytoken: {token['name']}",
                'enabled': True
            }
        return None

    def format_for_env(self, token):
        """Format token as environment variable."""
        if token['type'] == 'aws_key':
            return {
                'AWS_ACCESS_KEY_ID': token['access_key'],
                'AWS_SECRET_ACCESS_KEY': token['secret_key']
            }
        elif token['type'] == 'api_key':
            return {
                'API_KEY': token['api_key'],
                'API_SECRET': token['api_secret']
            }
        return None

    def format_alert(self, token, trigger_info=None):
        """Format honeytoken trigger for alerts."""
        lines = [
            f"Honeytoken Triggered: {token.get('name')}",
            f"Type: {token.get('type')}",
            f"ID: {token.get('id')}",
            f"Trigger #{token.get('trigger_count', 0)}",
        ]

        if trigger_info:
            if trigger_info.get('hostname'):
                lines.append(f"Hostname: {trigger_info['hostname']}")
            if trigger_info.get('username'):
                lines.append(f"Username: {trigger_info['username']}")
            if trigger_info.get('ip'):
                lines.append(f"IP: {trigger_info['ip']}")

        return '\n'.join(lines)

    def export_tokens(self, path):
        """Export all tokens to a file."""
        with open(path, 'w') as f:
            json.dump(self.tokens, f, indent=2)

    def import_tokens(self, path):
        """Import tokens from a file."""
        with open(path, 'r') as f:
            imported = json.load(f)
            self.tokens.update(imported)
            self._save_tokens()
