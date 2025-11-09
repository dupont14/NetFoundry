#!/bin/bash

# ==============================
#  Master Script for Automation
#  (runs children under sudo if not root)
#  Runs kali_device_pipeline.py first, then network_analyzer.py
# ==============================

# --- Automatically use the directory this script is in ---
CODE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$CODE_DIR/logs"

# --- Find python3 binary ---
PYTHON="$(command -v python3 || echo /usr/bin/python3)"

# Create log directory if missing
mkdir -p "$LOG_DIR"

# If running as root, no sudo prefix needed; otherwise use sudo
if [ "$(id -u)" -eq 0 ]; then
  SUDO_CMD=""
else
  SUDO_CMD="sudo"
fi

echo "[+] CODE_DIR = $CODE_DIR"
echo "[+] LOG_DIR  = $LOG_DIR"
echo "[+] PYTHON   = $PYTHON"
if [ -n "$SUDO_CMD" ]; then
  echo "[+] Child scripts will run with sudo."
else
  echo "[+] Child scripts will run as root (no sudo needed)."
fi

# --- Start the main server once ---
echo "[+] Starting server.py..."
if [ -n "$SUDO_CMD" ]; then
  $SUDO_CMD -b $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 || {
      echo "[!] Failed to launch server.py with sudo -b; trying fallback..."
      $SUDO_CMD $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 &
  }
else
  nohup $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 &
fi
echo "[+] server.py launch attempted — check $LOG_DIR/server.log"

# --- Initialize timers ---
minute_counter=0

# --- Main loop ---
while true; do
    echo
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running periodic tasks..."

    # --- Run kali pipeline every 5 minutes (first) ---
    if (( minute_counter % 5 == 0 )); then
        echo "[+] Running kali_device_pipeline.py..."
        if [ -n "$SUDO_CMD" ]; then
            $SUDO_CMD $PYTHON "$CODE_DIR/kali_device_pipeline.py" >> "$LOG_DIR/kali_pipeline.log" 2>&1
        else
            $PYTHON "$CODE_DIR/kali_device_pipeline.py" >> "$LOG_DIR/kali_pipeline.log" 2>&1
        fi
    fi

    # --- Run network analyzer every 1 minute (after kali if applicable) ---
    echo "[+] Running network_analyzer.py..."
    if [ -n "$SUDO_CMD" ]; then
        $SUDO_CMD $PYTHON "$CODE_DIR/network_analyzer.py" \
            --interface wlan0 \
            --devices "$CODE_DIR/network-devices.json" \
            --duration 10 \
            --output-dir "$CODE_DIR/output" \
            >> "$LOG_DIR/network_analyzer.log" 2>&1
    else
        $PYTHON "$CODE_DIR/network_analyzer.py" \
            --interface wlan0 \
            --devices "$CODE_DIR/network-devices.json" \
            --duration 10 \
            --output-dir "$CODE_DIR/output" \
            >> "$LOG_DIR/network_analyzer.log" 2>&1
    fi

    # Increment and wrap minute counter
    ((minute_counter++))
    if ((minute_counter >= 10000)); then
        minute_counter=0
    fi

    # --- Wait 60 seconds before next cycle ---
    sleep 60
done

