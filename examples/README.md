# WatchDog Examples

This directory contains example configurations and usage patterns.

## Quick Examples

### 1. Basic Setup

```bash
# Install
pip install -r requirements.txt

# Configure
python installer.py

# Create canary
python build/build.py --type bat --name passwords --decoy passwords
```

### 2. Discord Integration

```bash
# Create config with Discord
python -c "
import yaml
config = {
    'notifications': {
        'discord': {
            'enabled': True,
            'webhook_url': 'YOUR_DISCORD_WEBHOOK_URL'
        }
    },
    'rate_limit': 5
}
with open('config.yaml', 'w') as f:
    yaml.dump(config, f)
print('Config saved!')
"

# Create and test canary
python build/build.py --type bat --name test_canary
```

### 3. Multiple Canaries

```bash
# Create several canaries for different locations
python build/build.py --type bat --name passwords --decoy passwords
python build/build.py --type bat --name financial_records --decoy financial
python build/build.py --type bat --name crypto_wallet --decoy crypto
python build/build.py --type ps1 --name server_credentials --decoy credentials
```

### 4. Honeytoken Creation

```bash
# Create fake AWS keys
python -c "
from modules.honeytokens import HoneytokenManager
hm = HoneytokenManager()

# AWS key
aws = hm.generate_token('aws_key', 'Production AWS')
print(f'AWS Access Key: {aws[\"access_key\"]}')
print(f'AWS Secret Key: {aws[\"secret_key\"]}')

# Database password
db = hm.generate_token('password', 'Database Admin')
print(f'DB Username: {db[\"username\"]}')
print(f'DB Password: {db[\"password\"]}')
"
```

### 5. View Alerts

```bash
# Check alert count
python -c "from modules.logger import Logger; l = Logger(); print(f'Alerts: {l.get_alert_count()}')"

# View recent alerts
python -c "
from modules.logger import Logger
import json
l = Logger()
alerts = l.get_alerts(5)
for a in alerts:
    print(json.dumps(a, indent=2))
"
```

## Use Cases

### Home User

Protect your personal computer:

```bash
# Create a fake password file
python build/build.py --type bat --name passwords --decoy passwords

# Place on Desktop
copy build\passwords.bat "%USERPROFILE%\Desktop\passwords.bat"
```

### Small Business

Monitor shared computers:

```bash
# Create multiple canaries
python build/build.py --type all --name employee_handbook --decoy documents
python build/build.py --type all --name salary_info --decoy financial

# Deploy to shared drive
copy build\employee_handbook.* "\\server\shared\"
```

### Security Researcher

Test your security setup:

```bash
# Create with geofencing
python -c "
import yaml
config = {
    'geofencing': {
        'enabled': True,
        'allowed_countries': ['US'],
        'blocked_countries': []
    },
    'threat_intel': {
        'enabled': True,
        'virustotal_api_key': 'YOUR_KEY'
    }
}
with open('config.yaml', 'w') as f:
    yaml.dump(config, f)
"

# Create canary
python build/build.py --type bat --name security_test --decoy credentials
```
