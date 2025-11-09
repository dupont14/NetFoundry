# NetFoundry

A comprehensive network monitoring and analysis tool that automatically discovers devices on your local network and provides real-time traffic analysis with an intuitive web interface.

## Features

- 🔍 **Automatic Device Discovery**: Scans your local network to discover all connected devices using Nmap and ARP scanning
- 📊 **Real-Time Traffic Analysis**: Captures and analyzes network traffic for all devices using Wireshark/tshark
- 🌐 **Interactive Web Interface**: Beautiful, modern web UI with:
  - Circular network topology visualization
  - Real-time device status indicators (green/gray dots)
  - Detailed device information and traffic statistics
  - Individual device pages with live traffic monitoring
- 📈 **Traffic Statistics**: Tracks packets, bytes, upload/download speeds for each device
- 🔐 **Port Scanning**: Identifies open ports and services on discovered devices
- 🏷️ **Device Identification**: MAC address vendor lookup and OS detection
- ⚡ **Live Traffic Capture**: Start/stop live traffic monitoring for individual devices

## Requirements

### System Requirements
- macOS or Linux
- Python 3.6+
- Root/sudo access (required for packet capture)

### Software Dependencies
- **Wireshark/tshark**: For network packet capture and analysis
  - macOS: `brew install wireshark`
  - Linux (Debian/Ubuntu): `sudo apt-get install tshark`
  - Linux (RHEL/CentOS): `sudo yum install wireshark`
- **Nmap**: For network scanning and device discovery
  - macOS: `brew install nmap`
  - Linux: `sudo apt-get install nmap`
- **Python packages**:
  - `manuf` (optional, for MAC vendor lookup): `pip3 install --user manuf`
  - `requests` (optional): `pip3 install --user requests`

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd NetFoundry
   ```

2. **Install dependencies** (see Requirements above)

3. **Configure network interface** (if needed):
   - Edit `bashscheduler.sh` and change `en0` to your network interface
   - Common interfaces: `en0` (macOS), `eth0` (Linux), `wlan0` (Linux WiFi)

4. **Make scripts executable**:
   ```bash
   chmod +x working_folder/bashscheduler.sh
   ```

## Usage

### Quick Start

1. **Start the monitoring system**:
   ```bash
   cd working_folder
   sudo ./bashscheduler.sh
   ```

   This will:
   - Start the web server on port 8000
   - Perform an initial device discovery scan
   - Begin continuous traffic analysis (every 10 seconds)

2. **Access the web interface**:
   Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

3. **View your network**:
   - The main page shows all discovered devices in a circular topology
   - Click on any device to see detailed information and live traffic
   - Use the "Scan" button to manually trigger a new device discovery

### Manual Component Execution

If you prefer to run components individually:

**Start the web server**:
```bash
cd working_folder
python3 server.py
```

**Run device discovery** (one-time scan):
```bash
sudo python3 kali_device_pipeline.py
```

**Run traffic analysis** (continuous):
```bash
sudo python3 network_analyzer.py --interface en0 --devices network-devices.json --duration 10 --output-dir traffic_data
```

## Project Structure

```
NetFoundry/
├── README.md
├── LICENSE
├── working_folder/
│   ├── bashscheduler.sh          # Main automation script
│   ├── server.py                  # Web server and API
│   ├── kali_device_pipeline.py   # Device discovery
│   ├── network_analyzer.py       # Traffic capture and analysis
│   ├── index.html                # Main web interface
│   ├── device.html               # Individual device page
│   ├── network-devices.json      # Discovered devices database
│   ├── logs/                      # Application logs
│   ├── traffic_data/             # Traffic captures and summaries
│   └── output/                    # Additional output files
```

## Configuration

### Network Interface
Edit `bashscheduler.sh` and change the `--interface` parameter:
- macOS: Usually `en0` for Ethernet or `en1` for WiFi
- Linux: Usually `eth0` for Ethernet or `wlan0` for WiFi

### Scan Frequency
- Device discovery: Runs once at startup (can be triggered manually via web UI)
- Traffic analysis: Runs every 10 seconds (configurable in `bashscheduler.sh`)

### Port Configuration
The web server runs on port 8000 by default. To change it, edit `server.py`:
```python
server = HTTPServer(('', 8000), NetworkRequestHandler)  # Change 8000 to desired port
```

## Features in Detail

### Device Discovery
- Uses Nmap for ARP ping scanning to discover devices
- Extracts MAC addresses and vendor information
- Identifies routers and network topology
- Performs port scanning to detect open services

### Traffic Analysis
- Captures network traffic using tshark
- Analyzes packets, bytes, and transfer speeds
- Calculates upload/download bandwidth
- Identifies protocols and conversations
- Extracts HTTP requests and TLS SNI information

### Web Interface
- **Main Page (`index.html`)**:
  - Circular network topology with router at center
  - Device status indicators (green = active, gray = inactive)
  - Device list with traffic statistics
  - Auto-refreshes every 10 seconds

- **Device Page (`device.html`)**:
  - Detailed device information
  - Live traffic monitoring (start/stop capture)
  - Historical traffic statistics
  - Open ports and services
  - OS detection and vendor information

## API Endpoints

The web server provides the following API endpoints:

- `GET /api/devices` - Get all devices with traffic data
- `GET /api/device?ip=<IP>` - Get specific device information
- `GET /api/traffic/data?ip=<IP>` - Get traffic data for a device
- `POST /api/scan` - Trigger manual device discovery
- `POST /api/traffic/start` - Start live traffic capture for a device
- `POST /api/traffic/stop` - Stop live traffic capture

## Troubleshooting

### "tshark command not found"
Install Wireshark (see Requirements section)

### "Permission denied" errors
The scripts require root/sudo access for packet capture. Make sure you're running with `sudo`:
```bash
sudo ./bashscheduler.sh
```

### No devices discovered
- Check that you're on the correct network
- Verify your network interface name (`ifconfig` on macOS/Linux)
- Ensure Nmap is installed and accessible
- Check logs in `working_folder/logs/`

### No traffic data
- Devices may not be generating traffic during the capture window
- Verify tshark has proper permissions
- Check `traffic_data/all_summaries.json` for captured data
- Review logs in `working_folder/logs/network_analyzer.log`

### Port 8000 already in use
The scheduler automatically kills existing servers, but if issues persist:
```bash
lsof -i :8000
pkill -f "server.py"
```

## Logs

All logs are stored in `working_folder/logs/`:
- `server.log` - Web server logs
- `network_analyzer.log` - Traffic analysis logs
- `kali_pipeline.log` - Device discovery logs

## Security Notes

⚠️ **Important**: This tool requires root/sudo privileges to capture network traffic. Only run on networks you own or have explicit permission to monitor.

- The tool captures all network traffic on your local subnet
- Device information and traffic data are stored locally
- No data is transmitted outside your local machine
- Use responsibly and in accordance with applicable laws and regulations

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Acknowledgments

- Built with Python 3
- Uses Wireshark/tshark for packet capture
- Uses Nmap for network scanning
- Web interface built with vanilla JavaScript and modern CSS

