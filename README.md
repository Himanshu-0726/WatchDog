# WatchDog - Security Canary Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

**Defensive security canary/tripwire for authorized use only.**

> [!WARNING]
> This tool is designed for legitimate security monitoring on systems you own or have explicit authorization to monitor. Unauthorized use against systems you do not own is illegal and prohibited.

---

## What is WatchDog?

WatchDog is a **defensive security tool** that helps you detect unauthorized access to your computer. It works by creating "canary files" - decoy files that alert you when someone opens them.

```
┌─────────────────────────────────────────────────────────────┐
│                    HOW IT WORKS                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. You create a canary file (e.g., "passwords.txt")        │
│  2. You place it on your system                             │
│  3. Someone opens the file                                  │
│  4. WatchDog collects system info                           │
│  5. You get an alert via Discord/Telegram/Email             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Step 1: Install

```bash
# Clone the repository
git clone https://github.com/yourusername/watchdog.git
cd watchdog

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure

```bash
# Run the interactive setup wizard
python installer.py
```

The wizard will guide you through:
- Discord/Telegram webhook setup
- Geofencing configuration
- Threat intelligence API keys
- Email report settings

### Step 3: Create a Canary

```bash
# Create a simple canary file
python build/build.py --type bat --name passwords

# Create a canary with realistic decoy content
python build/build.py --type bat --name passwords --decoy passwords
```

### Step 4: Deploy

Copy the generated file to where you want to detect access:

```bash
# Example: Copy to Desktop
copy build\passwords.bat "%USERPROFILE%\Desktop\passwords.bat"
```

### Step 5: Get Alerted

When someone opens the file, you'll receive an alert like:

```
WatchDog Alert - Canary File Opened

Hostname: JOHNS-PC
Username: JohnDoe
Public IP: 203.0.113.45
OS: Windows 11
WiFi Network: HomeNetwork
Geolocation: New York, United States
```

---

## Features

<table>
<tr>
<td width="50%">

### Notifications
- Discord webhooks
- Telegram bots
- Email (SMTP)
- Local SQLite logging

</td>
<td width="50%">

### Detection
- System fingerprinting
- Geofencing
- Threat intelligence
- VPN/Proxy/Tor detection

</td>
</tr>
<tr>
<td>

### Security
- File integrity checking
- Process monitoring
- Incident management
- Encryption support

</td>
<td>

### Content
- Decoy file generator
- Honeytokens
- DNS canary
- Network fingerprinting

</td>
</tr>
</table>

---

## Usage Examples

### Example 1: Protect Your Passwords

```bash
# Create a fake password file that alerts when opened
python build/build.py --type bat --name passwords --decoy passwords

# Output:
# [+] Created: build\passwords.bat
# [+] Created decoy: build\passwords.txt
# [+] Integrity hash saved to config
```

### Example 2: Monitor Financial Documents

```bash
# Create a canary for financial records
python build/build.py --type ps1 --name tax_returns --decoy financial
```

### Example 3: Create Multiple Canaries

```bash
# Create both BAT and PS1 versions
python build/build.py --type all --name secret_document --decoy documents
```

### Example 4: Check DNS Canaries

```bash
# Check if any DNS canaries have been triggered
python sentinel.py --dns-check
```

---

## Configuration

### Basic Configuration

Edit `config.yaml`:

```yaml
# Notifications
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK"
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""

# Encryption
encryption:
  enabled: false
  key: ""

# Rate limiting (minutes between alerts)
rate_limit: 5
```

### Advanced Configuration

```yaml
# Geofencing - Only alert from unexpected locations
geofencing:
  enabled: true
  allowed_countries: ["US", "CA", "GB"]
  blocked_countries: []
  allowed_ips: ["203.0.113.0/24"]

# Threat Intelligence
threat_intel:
  enabled: true
  virustotal_api_key: "YOUR_API_KEY"
  abuseipdb_api_key: "YOUR_API_KEY"

# Process Monitoring
process_monitor:
  enabled: true

# SMTP Email Reports
smtp:
  enabled: false
  server: "smtp.gmail.com"
  port: 587
  username: ""
  password: ""
  from_email: ""
  to_emails: []
```

---

## Decoy Types

| Type | Description | Example Content |
|------|-------------|-----------------|
| `passwords` | Fake password list | Emails, banking, WiFi passwords |
| `financial` | Fake financial records | Bank accounts, credit cards, tax info |
| `credentials` | Fake server credentials | SSH keys, API keys, database passwords |
| `crypto` | Fake crypto wallets | Bitcoin, Ethereum, seed phrases |
| `personal` | Fake personal notes | Travel plans, medical info |
| `documents` | Fake document index | File hashes, document list |

> [!NOTE]
> All decoy content is completely randomly generated and fake. No real credentials are created.

---

## Project Structure

```
watchdog/
├── sentinel.py              # Main script (runs when canary is opened)
├── config.yaml              # Configuration file
├── installer.py             # Interactive setup wizard
├── build/
│   └── build.py             # Creates canary files
├── config/
│   └── suspicious_processes.json  # Process detection signatures
├── modules/
│   ├── fingerprint.py       # System info collection
│   ├── notifier.py          # Discord/Telegram alerts
│   ├── crypto.py            # Encryption
│   ├── logger.py            # SQLite logging
│   ├── decoy.py             # Decoy content generator
│   ├── geofencing.py        # Location filtering
│   ├── threatintel.py       # Threat intelligence
│   ├── incidents.py         # Incident management
│   ├── process_monitor.py   # Process detection
│   ├── honeytokens.py       # Credential honeytokens
│   ├── reports.py           # Email reports
│   ├── network_fingerprint.py  # VPN/proxy detection
│   └── dns_canary.py        # DNS hijacking detection
├── DISCLAIMER.md            # Authorized use guidelines
├── SECURITY.md              # Security policy
├── LICENSE                  # MIT License
└── requirements.txt         # Python dependencies
```

---

## Management

### View Alerts

```bash
# View alert count
python -c "from modules.logger import Logger; l = Logger(); print(f'Alerts: {l.get_alert_count()}')"

# View recent alerts
python -c "from modules.logger import Logger; l = Logger(); [print(f'[{a[\"id\"]}] {a[\"timestamp\"]} - {a[\"username\"]}@{a[\"hostname\"]}') for a in l.get_alerts(5)]"
```

### Manage Incidents

```bash
# View incident stats
python -c "from modules.incidents import IncidentManager; im = IncidentManager(); print(im.get_incident_stats())"
```

### Create Honeytokens

```bash
# Create a fake AWS key honeytoken
python -c "from modules.honeytokens import HoneytokenManager; hm = HoneytokenManager(); print(hm.generate_token('aws_key', 'Production AWS'))"
```

---

## What Gets Collected

When a canary file is opened, WatchDog collects:

| Data | Purpose |
|------|---------|
| Hostname | Identify which computer was accessed |
| Username | Identify who was logged in |
| Public IP | Network location |
| Private IP | Local network info |
| MAC Address | Device identifier |
| OS Details | Operating system version |
| WiFi Network | Network name (SSID) |
| Geolocation | Country, city, ISP |
| Processes | Running applications |
| Threat Score | Malicious IP detection |

---

## Security

- **File Integrity**: Detects if canary files are tampered with
- **Geofencing**: Only alerts from unexpected locations
- **Encryption**: Optional encryption for alert data
- **Rate Limiting**: Prevents alert spam
- **Local Storage**: Data stays on your system

See [SECURITY.md](SECURITY.md) for details.

---

## FAQ

**Q: Is this malware?**
A: No. WatchDog is a defensive security tool for monitoring your own systems. See [DISCLAIMER.md](DISCLAIMER.md).

**Q: Will this get my GitHub account suspended?**
A: No. WatchDog is a legitimate security tool with proper documentation and authorized use guidelines.

**Q: Can I use this on systems I don't own?**
A: No. This is prohibited and illegal.

**Q: Does it work on Mac/Linux?**
A: Yes. WatchDog is cross-platform.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Disclaimer

This software is provided for **authorized security monitoring only**. Users are responsible for complying with all applicable laws. See [DISCLAIMER.md](DISCLAIMER.md) for full details.
