# Contributing to WatchDog

Thank you for your interest in contributing to WatchDog! This document provides guidelines for contributing.

## Important Notice

WatchDog is a **defensive security tool** for authorized use only. All contributions must:

1. **Be defensive in nature** - No offensive capabilities
2. **Include proper documentation** - Clear purpose and authorized use
3. **Follow security best practices** - No hardcoded secrets, no malicious code
4. **Pass GitHub's content policy** - No malware, no unauthorized access tools

## How to Contribute

### Reporting Bugs

1. Check if the bug already exists in GitHub Issues
2. If not, create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS

### Suggesting Features

1. Check if the feature already exists or is planned
2. Create a new issue with:
   - Clear description of the feature
   - Use case (defensive security purpose)
   - How it improves the tool

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/watchdog.git
cd watchdog

# Install dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest
```

## Code Guidelines

### Python Style

- Follow PEP 8
- Use type hints where appropriate
- Write docstrings for all functions
- Keep functions focused and small

### Security Practices

- Never hardcode credentials
- Use environment variables for secrets
- Validate all user input
- Follow principle of least privilege

### Documentation

- Update README.md for new features
- Add docstrings to new functions
- Update USAGE.md if needed

## What NOT to Contribute

The following will be rejected:

- **Offensive capabilities** - Exploits, attacks, malware
- **Unauthorized access tools** - Password crackers, keyloggers
- **Stealth/evasion features** - Anti-detection, hiding capabilities
- **Social engineering tools** - Phishing, pretexting
- **Any illegal functionality**

## Testing

Before submitting a PR:

1. Test on multiple platforms (Windows, Linux, macOS)
2. Test with different Python versions (3.8+)
3. Verify no hardcoded secrets
4. Run any available linters
5. Test the setup wizard

## Code Review

All PRs will be reviewed for:

- **Security** - No malicious code
- **Quality** - Clean, maintainable code
- **Documentation** - Proper documentation
- **Purpose** - Defensive security use case

## Questions?

If you have questions about contributing, please open an issue.
