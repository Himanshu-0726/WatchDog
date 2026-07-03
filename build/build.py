"""WatchDog - Build System

Creates canary files (BAT/PS1) that trigger the sentinel when opened.
Supports decoy content generation for realistic-looking canaries.

This is a LEGITIMATE SECURITY TOOL for authorized use only.
See DISCLAIMER.md for authorized use guidelines.
"""

import os
import sys
import argparse
import hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
SENTINEL_PATH = os.path.join(PROJECT_DIR, 'sentinel.py')

sys.path.insert(0, PROJECT_DIR)
from modules.decoy import DecoyGenerator


def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def build_bat(output_name):
    """Create a BAT canary file that runs sentinel.py when opened.

    This file is a security canary - it alerts you when someone opens it.
    Place it on systems you own to detect unauthorized access.
    """
    bat_content = f'''@echo off
REM WatchDog - Security Canary File
REM This file monitors for unauthorized access.
REM If you see this message, the canary has been triggered.
echo WatchDog - Access detected
timeout /t 2 /nobreak >nul
pythonw "{SENTINEL_PATH}"
'''
    output_path = os.path.join(SCRIPT_DIR, f'{output_name}.bat')
    with open(output_path, 'w') as f:
        f.write(bat_content)
    print(f"[+] Created: {output_path}")
    return output_path

def build_bat_relative(output_name):
    """Create a BAT canary file using relative path to sentinel.py.

    The BAT file will look for sentinel.py in the same directory tree.
    Use this when deploying to a different location.
    """
    bat_content = r'''@echo off
REM WatchDog - Security Canary File
REM This file monitors for unauthorized access.
REM If you see this message, the canary has been triggered.
echo WatchDog - Access detected
timeout /t 2 /nobreak >nul
pythonw "%~dp0..\sentinel.py"
'''
    output_path = os.path.join(SCRIPT_DIR, f'{output_name}.bat')
    with open(output_path, 'w') as f:
        f.write(bat_content)
    print(f"[+] Created (relative path): {output_path}")
    return output_path


def build_ps1(output_name):
    """Create a PS1 canary file that runs sentinel.py when opened.

    This file is a security canary - it alerts you when someone opens it.
    Place it on systems you own to detect unauthorized access.
    """
    ps1_content = f'''# WatchDog - Security Canary File
# This file monitors for unauthorized access.
# If you see this message, the canary has been triggered.
Start-Sleep -Seconds 2
Start-Process -FilePath "pythonw" -ArgumentList "{SENTINEL_PATH}"
'''
    output_path = os.path.join(SCRIPT_DIR, f'{output_name}.ps1')
    with open(output_path, 'w') as f:
        f.write(ps1_content)
    print(f"[+] Created: {output_path}")
    return output_path


def build_decoy(output_name, decoy_type):
    """Create a decoy content file alongside the canary.

    All generated content is completely fake and for demonstration purposes only.
    """
    generator = DecoyGenerator()
    content = generator.generate(decoy_type)
    ext = generator.get_extension(decoy_type)

    decoy_path = os.path.join(SCRIPT_DIR, f'{output_name}{ext}')
    with open(decoy_path, 'w') as f:
        f.write(content)
    print(f"[+] Created decoy: {decoy_path}")
    return decoy_path


def save_integrity_config(canary_path, canary_name):
    """Save file hash to config for integrity checking."""
    import yaml
    config_path = os.path.join(PROJECT_DIR, 'config.yaml')

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    file_hash = get_file_hash(canary_path)
    config['integrity'] = {
        'enabled': True,
        'file_hash': file_hash,
        'canary_path': canary_path,
        'canary_name': canary_name
    }

    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    print(f"[+] Integrity hash saved to config")


def main():
    parser = argparse.ArgumentParser(
        description='WatchDog Build System - Creates security canary files'
    )
    parser.add_argument('--type', choices=['bat', 'ps1', 'all'], default='bat',
                        help='Output file type (default: bat)')
    parser.add_argument('--name', default='canary',
                        help='Output filename without extension (default: canary)')
    parser.add_argument('--decoy', choices=['passwords', 'financial', 'credentials', 'crypto', 'personal', 'documents'],
                        help='Generate decoy content file (all content is fake)')
    parser.add_argument('--no-integrity', action='store_true',
                        help='Skip saving integrity hash to config')
    parser.add_argument('--relative', action='store_true',
                        help='Use relative path (for deploying to other machines)')
    args = parser.parse_args()

    print("=" * 50)
    print("  WatchDog Build System")
    print("  Security Canary File Generator")
    print("=" * 50)
    print("  For authorized use only. See DISCLAIMER.md")

    if not os.path.exists(SENTINEL_PATH):
        print(f"[-] sentinel.py not found at: {SENTINEL_PATH}")
        sys.exit(1)

    canary_path = None
    if args.type in ('bat', 'all'):
        if args.relative:
            canary_path = build_bat_relative(args.name)
        else:
            canary_path = build_bat(args.name)
    if args.type in ('ps1', 'all'):
        canary_path = build_ps1(args.name)

    if args.decoy:
        build_decoy(args.name, args.decoy)

    if canary_path and not args.no_integrity:
        save_integrity_config(canary_path, args.name)

    print("\n[+] Build complete!")
    print("    Place the generated file on systems YOU OWN to detect unauthorized access.")
    print("    When opened, it will send you an alert with system information.")
    if args.decoy:
        print(f"    Decoy file ({args.decoy}) created. All content is fake.")


if __name__ == '__main__':
    main()
