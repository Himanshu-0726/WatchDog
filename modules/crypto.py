"""WatchDog - Encryption Module"""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryptor:
    """Handles encryption/decryption for alert data."""

    def __init__(self, key=None):
        if key:
            self.key = key.encode() if isinstance(key, str) else key
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    @classmethod
    def from_password(cls, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        instance = cls(key)
        instance.salt = salt
        return instance

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)

    def encrypt_dict(self, data):
        json_bytes = json.dumps(data, default=str).encode('utf-8')
        encrypted = self.encrypt(json_bytes)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt_dict(self, data):
        encrypted = base64.urlsafe_b64decode(data.encode('utf-8'))
        decrypted = self.decrypt(encrypted)
        return json.loads(decrypted.decode('utf-8'))

    def get_key(self):
        return self.key.decode('utf-8')

    def save_key(self, path):
        with open(path, 'w') as f:
            f.write(self.get_key())

    @classmethod
    def load_key(cls, path):
        with open(path, 'r') as f:
            key = f.read().strip()
        return cls(key)
