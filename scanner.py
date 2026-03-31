#!/usr/bin/env python3
"""
Axios Supply Chain Attack Scanner
Detects malicious packages from March 31, 2026 npm compromise

Usage: python3 scanner.py /path/to/parent/directory
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional

# Malicious packages to detect
MALICIOUS_PACKAGES = {
    'axios': {'1.14.1', '0.30.4'},
    'plain-crypto-js': {'4.2.1'}
}

# Attack timestamp - packages published on/after this date could be compromised
# March 31, 2026
ATTACK_TIMESTAMP = datetime(2026, 3, 31, tzinfo=timezone.utc).timestamp()

# Suspicious patterns
SUSPICIOUS_PATTERNS = [
    r'plain-crypto-js',
    r'axios@1\.14\.1',
    r'axios@0\.30\.4',
]


class Colors:
    """Terminal colors"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'


class Scanner:
    def __init__(self, root_path: str, use_colors: bool = True):
        self.root_path = Path(root_path).resolve()
        self.threats: List[Dict] = []
        self.warnings: List[Dict] = []
        self.scanned_projects: Set[str] = set()
        self.skipped_projects: Set[str] = set()  # Projects skipped due to old timestamps
        self.scan_time = datetime.now()
        self.use_colors = use_colors
        
    def log(self, message: str, color: str = Colors.CYAN):
        """Print colored message (only if colors enabled)"""
        if self.use_colors:
            print(f"{color}{message}{Colors.RESET}")
        else:
            print(message)
        
    def scan(self) -> None:
        """Main scan entry point"""
        self.log(f"🔍 Scanning for Axios Supply Chain Attack indicators...", Colors.CYAN)
        self.log(f"Root: {self.root_path}", Colors.CYAN)
        self.log(f"Time: {self.scan_time.isoformat()}\n", Colors.CYAN)
        
        # Scan local projects
        self._scan_local_projects()
        
        # Scan global installations
        self._scan_global_installs()
        
        # Scan Electron apps
        self._scan_electron_apps()
        
        # Scan other common locations
        self._scan_common_locations()
        
        # Generate report
        self._generate_report()
        
    def _scan_local_projects(self) -> None:
        """Scan all projects under root directory"""
        self.log("📁 Scanning local projects...", Colors.CYAN)
        
        # Find all lock files
        lock_patterns = ['**/package-lock.json', '**/yarn.lock', '**/pnpm-lock.yaml']
        lock_files: List[Path] = []
        
        for pattern in lock_patterns:
            try:
                lock_files.extend(self.root_path.glob(pattern))
            except Exception as e:
                self.warnings.append({
                    'type': 'glob_error',
                    'message': f"Failed to search pattern {pattern}: {e}",
                    'path': str(self.root_path)
                })
        
        self.log(f"Found {len(lock_files)} lock files", Colors.GREEN)
        
        # Scan each lock file
        for lock_file in lock_files:
            self._scan_lock_file(lock_file)
            
        # Also scan node_modules directly (in case no lock file or outdated)
        self._scan_node_modules_directly()
        
    def _scan_lock_file(self, lock_file: Path) -> None:
        """Scan a single lock file"""
        project_path = lock_file.parent
        project_name = project_path.name or str(project_path)
        
        if str(project_path) in self.scanned_projects:
            return
            
        # Check if lock file was modified before the attack - skip if so
        try:
            lock_mtime = lock_file.stat().st_mtime
            if lock_mtime < ATTACK_TIMESTAMP:
                # Project last touched before attack - cannot be compromised
                self.skipped_projects.add(str(project_path))
                self.scanned_projects.add(str(project_path))  # Count as processed
                return
        except Exception:
            pass  # If we can't get mtime, scan anyway
            
        self.scanned_projects.add(str(project_path))
        
        try:
            content = lock_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            self.warnings.append({
                'type': 'read_error',
                'message': f"Failed to read {lock_file}: {e}",
                'path': str(lock_file)
            })
            return
            
        self.log(f"  Scanning: {lock_file.relative_to(self.root_path)}...", Colors.CYAN)
        
        # Parse based on lock file type
        if lock_file.name == 'package-lock.json':
            self._parse_npm_lock(content, lock_file, project_path)
        elif lock_file.name == 'yarn.lock':
            self._parse_yarn_lock(content, lock_file, project_path)
        elif lock_file.name == 'pnpm-lock.yaml':
            self._parse_pnpm_lock(content, lock_file, project_path)
            
    def _parse_npm_lock(self, content: str, lock_file: Path, project_path: Path) -> None:
        """Parse npm package-lock.json"""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            self.warnings.append({
                'type': 'parse_error',
                'message': f"Invalid JSON in {lock_file}: {e}",
                'path': str(lock_file)
            })
            return
            
        # Check dependencies (npm v2 format)
        deps = data.get('dependencies', {})
        if isinstance(deps, dict):
            for pkg_name, pkg_info in deps.items():
                if isinstance(pkg_info, dict):
                    version = pkg_info.get('version', '')
                    self._check_package(pkg_name, version, 'package-lock.json', lock_file, project_path)
                    
                    # Check nested dependencies
                    nested_deps = pkg_info.get('dependencies', {})
                    if isinstance(nested_deps, dict):
                        for nested_name, nested_info in nested_deps.items():
                            if isinstance(nested_info, dict):
                                nested_version = nested_info.get('version', '')
                                self._check_package(nested_name, nested_version, 
                                                  f'package-lock.json (nested in {pkg_name})', 
                                                  lock_file, project_path)
                                                  
        # Check packages (npm v3+ format)
        packages = data.get('packages', {}).get('', {}).get('dependencies', {})
        if isinstance(packages, dict):
            for pkg_name, version in packages.items():
                if isinstance(version, str):
                    self._check_package(pkg_name, version, 'package-lock.json (packages)', 
                                       lock_file, project_path)
                                       
    def _parse_yarn_lock(self, content: str, lock_file: Path, project_path: Path) -> None:
        """Parse yarn.lock file"""
        # Yarn lock format: "package@version":
        #   version "x.x.x"
        current_pkg = None
        
        for line in content.split('\n'):
            # Match package declaration
            match = re.match(r'^"?([^@]+)@[^"]+"?:', line)
            if match:
                current_pkg = match.group(1)
                
            # Match version line
            version_match = re.match(r'\s+version\s+"([^"]+)"', line)
            if version_match and current_pkg:
                version = version_match.group(1)
                self._check_package(current_pkg, version, 'yarn.lock', lock_file, project_path)
                current_pkg = None
                
    def _parse_pnpm_lock(self, content: str, lock_file: Path, project_path: Path) -> None:
        """Parse pnpm-lock.yaml file"""
        # pnpm uses YAML format
        # Look for package entries like:
        # /package/version:
        #   resolution: {integrity: ...}
        
        for line in content.split('\n'):
            # Match package path
            match = re.match(r'^/([^/]+)/([^:]+):', line)
            if match:
                pkg_name = match.group(1)
                if pkg_name.startswith('@'):
                    # Scoped package
                    continue
                version = match.group(2)
                self._check_package(pkg_name, version, 'pnpm-lock.yaml', lock_file, project_path)
                
    def _check_package(self, name: str, version: str, source: str, 
                      lock_file: Path, project_path: Path) -> None:
        """Check if a package is malicious"""
        if name in MALICIOUS_PACKAGES:
            if version in MALICIOUS_PACKAGES[name]:
                threat = {
                    'package': name,
                    'version': version,
                    'source': source,
                    'project': str(project_path),
                    'lock_file': str(lock_file),
                    'severity': 'CRITICAL',
                    'description': f'Malicious {name} version {version} detected'
                }
                self.threats.append(threat)
                self.log(f"    ⚠️  THREAT: {name}@{version} in {source}", Colors.RED)
                
    def _scan_node_modules_directly(self) -> None:
        """Scan node_modules directories directly"""
        self.log("📦 Scanning node_modules directories directly...", Colors.CYAN)
        
        try:
            node_modules_paths = list(self.root_path.glob('**/node_modules'))
        except Exception as e:
            self.warnings.append({
                'type': 'glob_error',
                'message': f"Failed to find node_modules: {e}",
                'path': str(self.root_path)
            })
            return
            
        for nm_path in node_modules_paths:
            self._scan_single_node_modules(nm_path)
            
    def _scan_single_node_modules(self, nm_path: Path) -> None:
        """Scan a single node_modules directory"""
        project_path = nm_path.parent
        
        # Check if node_modules was modified before the attack - skip if so
        try:
            nm_mtime = nm_path.stat().st_mtime
            if nm_mtime < ATTACK_TIMESTAMP:
                # node_modules last touched before attack - skip
                return
        except Exception:
            pass  # If we can't get mtime, scan anyway
        
        # Check for malicious packages directly
        for pkg_name in MALICIOUS_PACKAGES:
            pkg_path = nm_path / pkg_name
            if pkg_path.exists() and pkg_path.is_dir():
                # Try to get version from package.json
                pkg_json = pkg_path / 'package.json'
                if pkg_json.exists():
                    try:
                        data = json.loads(pkg_json.read_text(encoding='utf-8', errors='ignore'))
                        version = data.get('version', 'unknown')
                        if version in MALICIOUS_PACKAGES[pkg_name]:
                            threat = {
                                'package': pkg_name,
                                'version': version,
                                'source': 'node_modules (direct)',
                                'project': str(project_path),
                                'lock_file': str(pkg_json),
                                'severity': 'CRITICAL',
                                'description': f'Malicious {pkg_name} version {version} found in node_modules'
                            }
                            if threat not in self.threats:
                                self.threats.append(threat)
                                self.log(f"    ⚠️  THREAT: {pkg_name}@{version} in node_modules", Colors.RED)
                    except Exception:
                        pass
                        
    def _get_npm_global_path(self) -> Optional[Path]:
        """Try multiple methods to find npm global path, works with sudo"""
        # Method 1: Try running npm directly
        try:
            result = subprocess.run(['npm', 'root', '-g'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except:
            pass
        
        # Method 2: Check common NVM paths (for sudo scenarios)
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
            Path('/opt/node_modules'),
            home / '.npm-global' / 'lib' / 'node_modules',
        ]
        for path in common_paths:
            if path.exists():
                return path
        
        return None
    
    def _scan_global_installs(self) -> None:
        """Scan global npm installations"""
        self.log("🌍 Scanning global npm installations...", Colors.CYAN)
        
        # Check if running as root
        running_as_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        if running_as_root:
            self.log("  Note: Running as root, checking NVM and common paths...", Colors.YELLOW)
        
        # Get global npm root using multiple methods
        global_root = self._get_npm_global_path()
        
        if global_root and global_root.exists():
            self._scan_single_node_modules(global_root)
            self.log(f"  Scanned: {global_root}", Colors.GREEN)
        else:
            if running_as_root:
                self.warnings.append({
                    'type': 'npm_not_found',
                    'message': 'npm not found in PATH when running as root. This is common with NVM. Try running without sudo, or manually specify the global node_modules path.',
                    'path': 'global'
                })
            else:
                self.warnings.append({
                    'type': 'npm_not_found',
                    'message': 'npm command not found, skipping global scan',
                    'path': 'global'
                })
            
    def _scan_electron_apps(self) -> None:
        """Scan Electron apps in common locations"""
        self.log("⚛️  Scanning Electron apps...", Colors.CYAN)
        
        electron_locations = [
            Path.home() / '.config',  # Linux Electron apps
            Path.home() / '.local/share',  # Linux local apps
            Path('/usr/lib'),  # System-wide apps
            Path('/opt'),  # Opt installs
        ]
        
        # Also check for .asar files (Electron app archives)
        for location in electron_locations:
            if location.exists():
                try:
                    # Look for node_modules in Electron apps
                    for nm_path in location.glob('**/node_modules'):
                        if 'electron' in str(nm_path).lower() or '.asar' in str(nm_path):
                            self._scan_single_node_modules(nm_path)
                            
                    # Look for app.asar.unpacked directories
                    for asar_path in location.glob('**/*.asar.unpacked'):
                        if asar_path.is_dir():
                            nm_path = asar_path / 'node_modules'
                            if nm_path.exists():
                                self._scan_single_node_modules(nm_path)
                                
                except Exception as e:
                    self.warnings.append({
                        'type': 'electron_scan_error',
                        'message': f"Error scanning {location}: {e}",
                        'path': str(location)
                    })
                    
    def _scan_common_locations(self) -> None:
        """Scan other common Node.js installation locations"""
        self.log("🔎 Scanning common Node.js locations...", Colors.CYAN)
        
        common_paths = [
            Path('/usr/local/lib/node_modules'),
            Path('/usr/lib/node_modules'),
            Path('/opt/node_modules'),
        ]
        
        for path in common_paths:
            if path.exists():
                self._scan_single_node_modules(path)
                self.log(f"  Scanned: {path}", Colors.GREEN)
                
        # Check for CLI tools
        self._scan_cli_tools()
        
    def _scan_cli_tools(self) -> None:
        """Scan specific CLI tools like opencode"""
        self.log("🔧 Scanning CLI tools...", Colors.CYAN)
        
        # Common CLI tool locations
        cli_paths = [
            Path.home() / '.local/share/opencode',
            Path.home() / '.opencode',
            Path.home() / '.npm-global',
            Path.home() / '.nvm/versions',
        ]
        
        for cli_path in cli_paths:
            if cli_path.exists():
                for nm_path in cli_path.rglob('node_modules'):
                    if nm_path.is_dir():
                        self._scan_single_node_modules(nm_path)
                        
    def _generate_report(self) -> None:
        """Generate markdown report"""
        report_path = self.root_path / f'axios_scan_report_{self.scan_time.strftime("%Y%m%d_%H%M%S")}.md'
        
        report_lines = [
            "# Axios Supply Chain Attack Scan Report",
            "",
            f"**Scan Date:** {self.scan_time.isoformat()}",
            f"**Root Directory:** {self.root_path}",
            f"**Projects Scanned:** {len(self.scanned_projects)}",
            "",
            "## ⚠️ Threats Found",
            "",
        ]
        
        if self.threats:
            report_lines.append(f"**CRITICAL: {len(self.threats)} malicious package(s) detected!**")
            report_lines.append("")
            for i, threat in enumerate(self.threats, 1):
                report_lines.extend([
                    f"### Threat #{i}",
                    "",
                    f"- **Package:** `{threat['package']}@{threat['version']}`",
                    f"- **Severity:** {threat['severity']}",
                    f"- **Source:** {threat['source']}",
                    f"- **Project:** `{threat['project']}`",
                    f"- **File:** `{threat['lock_file']}`",
                    f"- **Description:** {threat['description']}",
                    "",
                ])
                
            report_lines.extend([
                "## 🚨 Immediate Actions Required",
                "",
                "1. **Remove the malicious packages immediately:**",
                "   ```bash",
                "   npm uninstall axios",
                "   npm uninstall plain-crypto-js",
                "   ```",
                "",
                "2. **Clean npm cache:**",
                "   ```bash",
                "   npm cache clean --force",
                "   ```",
                "",
                "3. **Reinstall from known good versions:**",
                "   ```bash",
                "   npm install axios@1.14.0  # or latest safe version",
                "   ```",
                "",
                "4. **Check for signs of compromise:**",
                "   - Review recent system activity",
                "   - Check for unexpected processes",
                "   - Scan for additional malware",
                "",
            ])
        else:
            report_lines.extend([
                "✅ **No malicious packages detected!**",
                "",
                "Your projects appear to be safe from the Axios supply chain attack.",
                "",
            ])
            
        # Add warnings section
        if self.warnings:
            report_lines.extend([
                "## ⚠️ Scan Warnings",
                "",
                "The following issues were encountered during scanning:",
                "",
            ])
            for warning in self.warnings:
                report_lines.append(f"- **{warning['type']}:** {warning['message']}")
            report_lines.append("")
            
        # Add summary
        report_lines.extend([
            "## 📊 Scan Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Projects Scanned | {len(self.scanned_projects)} |",
            f"| Projects Skipped (pre-attack) | {len(self.skipped_projects)} |",
            f"| Threats Found | {len(self.threats)} |",
            f"| Warnings | {len(self.warnings)} |",
            "",
            f"**Attack Detection Threshold:** March 31, 2026",
            "",
            f"Projects with lock files or node_modules last modified before this date were automatically skipped.",
            "",
        ])
        
        for pkg, versions in MALICIOUS_PACKAGES.items():
            report_lines.append(f"| `{pkg}` | {', '.join(versions)} |")
            
        report_lines.extend([
            "",
            "## 📚 References",
            "",
            "- [Snyk Blog Post](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)",
            "- [The Hacker News Report](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)",
            "",
            "---",
            "",
            "*Report generated by axios-supply-chain-scanner*",
        ])
        
        # Write report
        report_content = '\n'.join(report_lines)
        report_path.write_text(report_content, encoding='utf-8')
        
        self.log(f"\n{'='*60}", Colors.CYAN)
        if self.threats:
            self.log(f"🚨 SCAN COMPLETE: {len(self.threats)} THREAT(S) FOUND!", Colors.RED)
        else:
            self.log(f"✅ SCAN COMPLETE: No threats found", Colors.GREEN)
        self.log(f"📄 Report saved to: {report_path}", Colors.CYAN)
        self.log(f"{'='*60}\n", Colors.CYAN)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py /path/to/parent/directory")
        print("Example: python3 scanner.py /home/user/projects")
        sys.exit(1)
        
    root_path = sys.argv[1]
    
    if not os.path.exists(root_path):
        print(f"Error: Path does not exist: {root_path}")
        sys.exit(1)
        
    if not os.path.isdir(root_path):
        print(f"Error: Path is not a directory: {root_path}")
        sys.exit(1)
    
    # Disable colors if NO_COLOR is set or output is not a terminal
    use_colors = not os.environ.get('NO_COLOR') and sys.stdout.isatty()
    scanner = Scanner(root_path, use_colors=use_colors)
    scanner.scan()


if __name__ == '__main__':
    main()
