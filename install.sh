#!/bin/bash
# RUZZ Installer
# by zoro_rj

set -e

echo ""
echo "  Installing RUZZ..."
echo ""

# check python3
if ! command -v python3 &> /dev/null; then
    echo "  [ERROR] python3 not found. Install it first."
    exit 1
fi

# copy to /usr/local/bin
sudo cp fuzzer.py /usr/local/bin/ruzz
sudo chmod +x /usr/local/bin/ruzz

echo ""
echo "  Done! Run 'ruzz' from anywhere."
echo ""