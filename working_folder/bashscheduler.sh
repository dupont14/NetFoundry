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
echo "[+] ========================================"
echo "[+] Starting server.py..."
echo "[+] ========================================"

# Check if server is already running
if lsof -i :8000 > /dev/null 2>&1; then
    echo "[!] Port 8000 is already in use. Killing existing server..."
    pkill -f "server.py" 2>/dev/null
    sleep 2
fi

if [ -n "$SUDO_CMD" ]; then
  $SUDO_CMD -b $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 || {
      echo "[!] Failed to launch server.py with sudo -b; trying fallback..."
      $SUDO_CMD $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 &
  }
else
  nohup $PYTHON "$CODE_DIR/server.py" >> "$LOG_DIR/server.log" 2>&1 &
fi

# Wait a moment and verify server started
sleep 2
if lsof -i :8000 > /dev/null 2>&1; then
    echo "[✓] Server is running on http://localhost:8000"
else
    echo "[!] WARNING: Server may not have started. Check $LOG_DIR/server.log"
fi
echo "[+] Server logs: $LOG_DIR/server.log"
echo ""

# --- Cleanup function to stop background processes ---
cleanup() {
    echo ""
    echo "[!] Shutting down..."
    if [ -n "$TRAFFIC_ANALYZER_PID" ]; then
        echo "[!] Stopping traffic analyzer (PID: $TRAFFIC_ANALYZER_PID)..."
        kill $TRAFFIC_ANALYZER_PID 2>/dev/null
        wait $TRAFFIC_ANALYZER_PID 2>/dev/null
    fi
    # Kill any running processes
    pkill -f "network_analyzer.py" 2>/dev/null
    pkill -f "tshark" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# --- Run device discovery once at startup ---
echo "[+] ========================================"
echo "[+] Running device discovery scan (one-time at startup)..."
echo "[+] ========================================"
START_TIME=$(date +%s)

if [ -n "$SUDO_CMD" ]; then
    $SUDO_CMD $PYTHON "$CODE_DIR/kali_device_pipeline.py" --quick >> "$LOG_DIR/kali_pipeline.log" 2>&1
    EXIT_CODE=$?
else
    $PYTHON "$CODE_DIR/kali_device_pipeline.py" --quick >> "$LOG_DIR/kali_pipeline.log" 2>&1
    EXIT_CODE=$?
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [ $EXIT_CODE -eq 0 ]; then
    echo "[✓] Device discovery completed in ${DURATION}s"
    echo "[+] Devices saved to network-devices.json"
else
    echo "[!] Device discovery completed with errors (exit code: $EXIT_CODE) in ${DURATION}s"
fi
echo "[📋] Logs: $LOG_DIR/kali_pipeline.log"
echo ""

# --- Start network traffic analyzer in background (runs every 10 seconds) ---
echo "[+] ========================================"
echo "[+] Starting network traffic analyzer loop (every 10 seconds)..."
echo "[+] ========================================"
(
    while true; do
        echo ""
        echo "[📊] [$(date '+%H:%M:%S')] Running network traffic analysis..."
        START_TIME=$(date +%s)
        
        if [ -n "$SUDO_CMD" ]; then
            $SUDO_CMD $PYTHON "$CODE_DIR/network_analyzer.py" \
                --interface en0 \
                --devices "$CODE_DIR/network-devices.json" \
                --duration 10 \
                --output-dir "$CODE_DIR/traffic_data" \
                >> "$LOG_DIR/network_analyzer.log" 2>&1
            EXIT_CODE=$?
        else
            $PYTHON "$CODE_DIR/network_analyzer.py" \
                --interface en0 \
                --devices "$CODE_DIR/network-devices.json" \
                --duration 10 \
                --output-dir "$CODE_DIR/traffic_data" \
                >> "$LOG_DIR/network_analyzer.log" 2>&1
            EXIT_CODE=$?
        fi
        
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        
        if [ $EXIT_CODE -eq 0 ]; then
            echo "[✓] Network traffic analysis completed in ${DURATION}s"
        else
            echo "[!] Network traffic analysis failed (exit code: $EXIT_CODE) in ${DURATION}s"
        fi
        echo "[📋] Logs: $LOG_DIR/network_analyzer.log"
        echo "[📁] Output: $CODE_DIR/traffic_data/"
        
        sleep 10  # Wait 10 seconds before next analysis
    done
) &
TRAFFIC_ANALYZER_PID=$!
echo "[+] Network traffic analyzer loop started (PID: $TRAFFIC_ANALYZER_PID)"
echo "[!] Press Ctrl+C to stop all processes"
echo ""

# --- Main loop just waits (traffic analyzer runs in background) ---
echo "[+] ========================================"
echo "[+] Traffic analyzer running in background"
echo "[+] Device discovery: completed (one-time scan)"
echo "[+] Traffic analysis: every 10 seconds"
echo "[+] ========================================"
echo ""

# Just wait and monitor
while true; do
    sleep 60
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] System running... (Traffic analyzer PID: $TRAFFIC_ANALYZER_PID)"
done

