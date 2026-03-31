#!/usr/bin/env python3
"""
Quick Axios Scanner - Scan current directory
Usage: Just run `python3 quick_scan.py` in any directory
       Or `python3 quick_scan.py --global-only` for global npm only
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime, timezone

MALICIOUS = {
    'axios': {'1.14.1', '0.30.4'},
    'plain-crypto-js': {'4.2.1'}
}

# Attack timestamp - March 31, 2026
ATTACK_TIMESTAMP = datetime(2026, 3, 31, tzinfo=timezone.utc).timestamp()

def get_npm_global_path():
    """Get global npm path, trying multiple methods"""
    # Method 1: Try npm command
    try:
        result = subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except:
        pass
    
    # Method 2: Check common NVM paths
    home = Path.home()
    nvm_base = home / '.nvm' / 'versions' / 'node'
    if nvm_base.exists():
        # Find the latest version or check all
        for version_dir in sorted(nvm_base.iterdir(), reverse=True):
            if version_dir.is_dir():
                global_path = version_dir / 'lib' / 'node_modules'
                if global_path.exists():
                    return global_path
    
    # Method 3: Check other common locations
    common_paths = [
        Path('/usr/local/lib/node_modules'),
        Path('/usr/lib/node_modules'),
        home / '.npm-global' / 'lib' / 'node_modules',
    ]
    for path in common_paths:
        if path.exists():
            return path
    
    return None

def check_lock_file(lock_path):
    """Quick check of a lock file"""
    # Skip if file was modified before attack
    try:
        if lock_path.stat().st_mtime < ATTACK_TIMESTAMP:
            return False  # Skip old files
    except:
        pass
    
    try:
        if lock_path.suffix == '.json':
            data = json.loads(lock_path.read_text())
            # Check dependencies
            deps = data.get('dependencies', {})
            if isinstance(deps, dict):
                for pkg, info in deps.items():
                    if isinstance(info, dict):
                        version = info.get('version', '')
                        if pkg in MALICIOUS and version in MALICIOUS[pkg]:
                            print(f"\n🚨 THREAT: {pkg}@{version} in {lock_path}")
                            return True
    except:
        pass
    return False

def scan_directory(path):
    """Scan a directory for threats"""
    threats = []
    skipped = 0
    
    # Find lock files
    for lock_file in path.rglob('package-lock.json'):
        if check_lock_file(lock_file):
            threats.append(str(lock_file))
            
    # Check node_modules directly (with timestamp check)
    for nm in path.rglob('node_modules'):
        # Skip if node_modules is too old
        try:
            if nm.stat().st_mtime < ATTACK_TIMESTAMP:
                skipped += 1
                continue
        except:
            pass
            
        for pkg_name in MALICIOUS:
            pkg_path = nm / pkg_name / 'package.json'
            if pkg_path.exists():
                try:
                    version = json.loads(pkg_path.read_text()).get('version', '')
                    if version in MALICIOUS[pkg_name]:
                        print(f"\n🚨 THREAT: {pkg_name}@{version} in node_modules")
                        threats.append(str(pkg_path))
                except:
                    pass
    
    return threats

def main():
    global_only = '--global-only' in sys.argv
    
    if global_only:
        print("🔍 Quick Axios Scanner - Global npm only")
        print("=" * 50)
    else:
        print("🔍 Quick Axios Scanner")
        print("=" * 50)
    
    threats = []
    cwd = Path.cwd()
    
    if not global_only:
        # Scan current directory
        print(f"\nScanning: {cwd}")
        threats = scan_directory(cwd)
    
    # Check global npm
    print("\nChecking global npm...")
    global_path = get_npm_global_path()
    
    if global_path and global_path.exists():
        print(f"Found global path: {global_path}")
        global_threats = scan_directory(global_path)
        threats.extend(global_threats)
    else:
        print("Could not find global npm installation")
    
    # Results
    print("\n" + "=" * 50)
    if threats:
        print(f"🚨 FOUND {len(threats)} THREAT(S)!")
        print("\nMalicious packages detected:")
        print("  - axios@1.14.1 or axios@0.30.4")
        print("  - plain-crypto-js@4.2.1")
        print("\nAction: Remove immediately!")
    else:
        print("✅ No threats found")
    
    # Save report
    report = f"""# Quick Scan Report - {datetime.now().isoformat()}

## Results
- **Scanned:** {cwd}
- **Threats:** {len(threats)}
- **Status:** {'🚨 COMPROMISED' if threats else '✅ CLEAN'}

## Threats
{chr(10).join(f'- {t}' for t in threats) if threats else 'None detected'}
"""
    
    report_path = Path('axios_quick_scan_report.md')
    report_path.write_text(report)
    print(f"\n📄 Report saved to: {report_path}")

if __name__ == '__main__':
    main()
