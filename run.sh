#!/usr/bin/env bash

# Set virtual environment folder name
VENV_DIR="venv"

# Detect if `python3` or `python` is available
if command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    echo "[ERROR] Python is not installed! Please install Python and try again."
    exit 1
fi

# Check if virtual environment exists, create it if not
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
fi

# Activate the virtual environment
source "$VENV_DIR/bin/activate"

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "[+] Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
fi

# Run the script with sudo while preserving the environment
echo "[+] Running main.py with sudo..."
sudo -E "$PYTHON" main.py

