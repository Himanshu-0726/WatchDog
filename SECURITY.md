# Security Policy

## Reporting Security Issues

If you discover a security vulnerability in WatchDog, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to: [your-email@example.com]
3. Include: Description, steps to reproduce, potential impact
4. Allow reasonable time for response before public disclosure

## Intended Use

WatchDog is designed for **defensive security monitoring**:

- Detect unauthorized access to your own systems
- Monitor canary files placed on your infrastructure
- Alert when sensitive files are accessed
- Track potential security incidents

## Not Intended For

This tool is **NOT** designed for:

- Offensive operations or penetration testing
- Unauthorized access to systems
- Malware distribution
- Any illegal activity

## Security Features

WatchDog includes these security features:

- **File integrity checking** - Detects tampering with canary files
- **Geofencing** - Restricts alerts to expected locations
- **Threat intelligence** - Checks IPs against known threat feeds
- **Encryption** - Optional encryption for alert data
- **Process monitoring** - Detects suspicious security tools

## Data Collection

When a canary file is triggered, the following information is collected:

- System hostname and username
- IP addresses (public and private)
- Operating system details
- WiFi network information
- Geolocation (country, city, ISP)

This data is collected **only from the system where the canary is deployed** (your own system).

## Data Storage

- Alerts are stored locally in SQLite database (`alerts.db`)
- No data is sent to external servers except configured notification channels
- You have full control over where data is sent

## License

This software is licensed under the MIT License. See LICENSE file for details.
