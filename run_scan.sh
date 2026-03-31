#!/bin/bash
# Make scripts executable and run full scan

echo "Axios Supply Chain Attack Scanner"
echo "=================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3."
    exit 1
fi

echo "✅ Python found: $(python3 --version)"
echo ""

# Usage
if [ $# -eq 0 ]; then
    echo "Usage:"
    echo "  ./run_scan.sh /path/to/projects        # Full recursive scan"
    echo "  ./run_scan.sh /path/to/projects -v     # Verbose scan with table"
    echo "  ./run_scan.sh --quick                  # Quick current directory scan"
    echo "  ./run_scan.sh --global                 # Scan global npm only"
    echo ""
    echo "Examples:"
    echo "  ./run_scan.sh /home/user/projects"
    echo "  ./run_scan.sh . -v"
    exit 1
fi

# Run appropriate scan
if [ "$1" == "--quick" ]; then
    echo "Running quick scan..."
    python3 "$SCRIPT_DIR/quick_scan.py"
elif [ "$1" == "--global" ]; then
    echo "Scanning global npm installations..."
    python3 "$SCRIPT_DIR/quick_scan.py" --global-only
else
    TARGET="$1"
    shift  # Remove first argument, keep rest (like -v, --verbose, etc.)
    
    if [ ! -d "$TARGET" ]; then
        echo "Error: Directory does not exist: $TARGET"
        exit 1
    fi
    
    echo "Running full scan on: $TARGET"
    if [ $# -gt 0 ]; then
        echo "Additional options: $@"
    fi
    echo "This may take a while for large directories..."
    echo ""
    python3 "$SCRIPT_DIR/scanner.py" "$TARGET" "$@"
fi
