# Axios Supply Chain Attack Scanner

Quick detection scripts for the March 31, 2026 npm axios compromise.

## What Happened

On March 31, 2026, malicious versions of axios (`1.14.1` and `0.30.4`) were published to npm that inject `plain-crypto-js@4.2.1` - a phantom dependency that deploys a Remote Access Trojan (RAT) via postinstall hook, targeting Windows, macOS, and Linux.

## Detection Targets

| Package | Malicious Versions |
|---------|-------------------|
| `axios` | `1.14.1`, `0.30.4` |
| `plain-crypto-js` | `4.2.1` |

## Installation

No installation required - just Python 3.x (pre-installed on most Linux systems).

```bash
git clone <repository-url>
cd axios-supplychain-attack
chmod +x run_scan.sh
```

## Usage

### Quick Scan (current directory)
```bash
python3 quick_scan.py
```

### Full Recursive Scan
```bash
# Scan all projects in a directory
python3 scanner.py /path/to/parent/directory

# Or use the bash wrapper
./run_scan.sh /path/to/parent/directory
```

### Scan Global npm Only
```bash
./run_scan.sh --global
```

## What Gets Scanned

- All `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` files
- All `node_modules` directories (direct package check)
- Global npm installations (including NVM paths)
- Electron apps (`~/.config`, `/opt`, etc.)
- CLI tools (opencode, etc.)

## Output

Scanner generates timestamped markdown reports (e.g., `axios_scan_report_20260331_123045.md`) with:
- List of detected threats
- Remediation steps
- Scan summary statistics
- Projects skipped (pre-attack date)

## Running as Root (sudo)

If you use NVM (Node Version Manager), the `npm` command may not be available when running with `sudo` because sudo preserves a different PATH environment.

**Solutions:**

1. **Run without sudo (recommended)**:
   ```bash
   python3 scanner.py /home/youruser/projects
   ```

2. **Or run as root with explicit PATH**:
   ```bash
   sudo -E env "PATH=$PATH" python3 scanner.py /path/to/projects
   ```

3. **The scanner will check common NVM paths even without npm in PATH**

## Performance Optimization

The scanner automatically skips projects that were last modified **before March 31, 2026** (the attack date), significantly reducing scan time on directories with old projects.

## License

MIT License - See LICENSE file

## Disclaimer

This tool is for security research and detection purposes. Always verify results and check official security advisories.
