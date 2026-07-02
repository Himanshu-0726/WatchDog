# WatchDog Usage Guide

This guide provides detailed instructions for using WatchDog.

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Creating Canaries](#creating-canaries)
4. [Deploying Canaries](#deploying-canaries)
5. [Monitoring Alerts](#monitoring-alerts)
6. [Advanced Features](#advanced-features)
7. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for cloning)

### Step-by-Step Installation

#### Option 1: Clone with Git

```bash
# Clone the repository
git clone https://github.com/yourusername/watchdog.git

# Navigate to the directory
cd watchdog

# Install dependencies
pip install -r requirements.txt
```

#### Option 2: Download ZIP

1. Download the ZIP file from GitHub
2. Extract to your desired location
3. Open a terminal in the extracted folder
4. Run: `pip install -r requirements.txt`

### Verify Installation

```bash
# Check if WatchDog is working
python sentinel.py --help
```

---

## Configuration

### Interactive Setup (Recommended)

Run the setup wizard:

```bash
python installer.py
```

The wizard will guide you through:

1. **Discord Setup**
   - Enable Discord alerts
   - Enter your webhook URL
   - How to get a webhook URL: Discord > Server Settings > Integrations > Webhooks > New Webhook

2. **Telegram Setup**
   - Enable Telegram alerts
   - Enter bot token (from @BotFather)
   - Enter chat ID (from @userinfobot)

3. **Encryption Setup**
   - Enable/disable encryption
   - Set encryption key (or auto-generate)

4. **Geofencing Setup**
   - Enable geofencing
   - Set allowed countries (ISO codes: US, CA, GB)
   - Set blocked countries
   - Whitelist specific IPs

5. **Threat Intelligence Setup**
   - Enable threat intel
   - Enter VirusTotal API key (free at virustotal.com)
   - Enter AbuseIPDB API key (free at abuseipdb.com)

6. **SMTP Setup**
   - Enable email reports
   - Configure SMTP server
   - Set email addresses

### Manual Configuration

Edit `config.yaml` directly:

```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/123456/abcdef"
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""

encryption:
  enabled: false
  key: ""

geofencing:
  enabled: false
  allowed_countries: []
  blocked_countries: []
  allowed_ips: []

threat_intel:
  enabled: false
  virustotal_api_key: ""
  abuseipdb_api_key: ""

process_monitor:
  enabled: true

smtp:
  enabled: false
  server: "smtp.gmail.com"
  port: 587
  username: ""
  password: ""
  from_email: ""
  to_emails: []

rate_limit: 5
```

---

## Creating Canaries

### Basic Canary

```bash
python build/build.py --type bat --name my_canary
```

This creates `my_canary.bat` in the `build/` directory.

### Canary with Decoy Content

```bash
python build/build.py --type bat --name passwords --decoy passwords
```

This creates:
- `passwords.bat` - The canary trigger file
- `passwords.txt` - Fake password file (realistic content)

### All Decoy Types

```bash
# Passwords
python build/build.py --type bat --name passwords --decoy passwords

# Financial records
python build/build.py --type bat --name finances --decoy financial

# Server credentials
python build/build.py --type bat --name server_keys --decoy credentials

# Crypto wallets
python build/build.py --type bat --name wallet --decoy crypto

# Personal notes
python build/build.py --type bat --name notes --decoy personal

# Document index
python build/build.py --type bat --name documents --decoy documents
```

### Create Both BAT and PS1

```bash
python build/build.py --type all --name canary --decoy passwords
```

This creates:
- `canary.bat` - For Windows users
- `canary.ps1` - For PowerShell users
- `passwords.txt` - Decoy content

---

## Deploying Canaries

### Where to Place Canaries

| Location | Use Case |
|----------|----------|
| Desktop | Detect if someone accesses your computer |
| Documents folder | Monitor sensitive document access |
| Downloads folder | Detect unauthorized downloads |
| USB drive | Detect USB theft |
| Network share | Monitor shared folder access |

### Deployment Examples

#### Windows

```powershell
# Copy to Desktop
copy build\passwords.bat "%USERPROFILE%\Desktop\passwords.bat"

# Copy to Documents
copy build\passwords.bat "%USERPROFILE%\Documents\passwords.bat"

# Copy to USB drive
copy build\passwords.bat "E:\passwords.bat"
```

#### Linux/macOS

```bash
# Copy to Desktop
cp build/passwords.bat ~/Desktop/passwords.bat

# Copy to Documents
cp build/passwords.bat ~/Documents/passwords.bat
```

### Best Practices

1. **Use realistic names**: `passwords.bat`, `tax_returns.bat`, `financial_records.bat`
2. **Place in obvious locations**: Desktop, Documents, Downloads
3. **Create multiple canaries**: Different files in different locations
4. **Don't tell anyone**: The canary only works if it's a secret

---

## Monitoring Alerts

### Discord Alerts

When a canary is triggered, you'll receive a Discord embed:

```
WatchDog Alert
Canary file has been opened

Hostname: JOHNS-PC
Username: JohnDoe
Public IP: 203.0.113.45
OS: Windows 11
WiFi Network: HomeNetwork
Geolocation: New York, United States
```

### Telegram Alerts

You'll receive a Telegram message with the same information.

### Local Logging

Alerts are stored in `alerts.db`. View them:

```bash
# Quick view
python -c "from modules.logger import Logger; l = Logger(); print(f'Total alerts: {l.get_alert_count()}')"

# View recent alerts
python -c "
from modules.logger import Logger
l = Logger()
alerts = l.get_alerts(10)
for a in alerts:
    print(f'[{a[\"id\"]}] {a[\"timestamp\"]} - {a[\"username\"]}@{a[\"hostname\"]} ({a[\"public_ip\"]})')
"
```

---

## Advanced Features

### Geofencing

Restrict alerts to specific locations:

```yaml
geofencing:
  enabled: true
  allowed_countries: ["US", "CA"]  # Only alert from US/Canada
  blocked_countries: ["CN", "RU"]  # Always alert from these
  allowed_ips: ["203.0.113.0/24"]  # Always allow this range
```

### Threat Intelligence

Check IPs against known threat feeds:

```yaml
threat_intel:
  enabled: true
  virustotal_api_key: "your_key"
  abuseipdb_api_key: "your_key"
```

### Honeytokens

Create fake credentials that alert when used:

```bash
# Create a fake AWS key
python -c "
from modules.honeytokens import HoneytokenManager
hm = HoneytokenManager()
token = hm.generate_token('aws_key', 'Production AWS')
print(f'Access Key: {token[\"access_key\"]}')
print(f'Secret Key: {token[\"secret_key\"]}')
"

# Create a fake password
python -c "
from modules.honeytokens import HoneytokenManager
hm = HoneytokenManager()
token = hm.generate_token('password', 'Admin Account')
print(f'Username: {token[\"username\"]}')
print(f'Password: {token[\"password\"]}')
"
```

### DNS Canaries

Monitor for DNS hijacking:

```bash
# Check DNS canaries
python sentinel.py --dns-check
```

### Email Reports

Get daily/weekly summaries:

```yaml
smtp:
  enabled: true
  server: "smtp.gmail.com"
  port: 587
  username: "you@gmail.com"
  password: "app_password"
  from_email: "you@gmail.com"
  to_emails: ["security@company.com"]
```

---

## Troubleshooting

### Common Issues

#### "Config not found"

```bash
# Run the setup wizard first
python installer.py
```

#### "Module not found"

```bash
# Install dependencies
pip install -r requirements.txt
```

#### "Discord webhook failed"

1. Check the webhook URL is correct
2. Make sure the webhook is active
3. Test with: `python installer.py` (option to test notifications)

#### "Telegram bot not responding"

1. Check bot token is correct
2. Make sure you've started a chat with the bot
3. Check chat ID is correct

### Debug Mode

Run with verbose output:

```bash
# Check what's happening
python -c "
from modules.fingerprint import Fingerprinter
f = Fingerprinter()
import json
print(json.dumps(f.collect_all(), indent=2))
"
```

### Test Notifications

```bash
# Test Discord/Telegram
python installer.py
# Choose 'y' when asked to test notifications
```

---

## Getting Help

- Read the [README](README.md)
- Check [DISCLAIMER.md](DISCLAIMER.md) for authorized use
- Open an issue on GitHub

---

## Legal Notice

This tool is for **authorized security monitoring only**. Users are responsible for complying with all applicable laws. See [DISCLAIMER.md](DISCLAIMER.md).
