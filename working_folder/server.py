from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import subprocess
import threading
import time
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import signal
import sys

# Global state for traffic captures
traffic_captures = {}  # {ip: {'process': subprocess, 'pcap_file': str, 'data': dict, 'lock': threading.Lock}}

class NetworkRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # API endpoints
        if path == '/api/device':
            self.handle_get_device()
        elif path == '/api/traffic/data':
            self.handle_get_traffic_data()
        elif path == '/api/devices':
            self.handle_get_devices_with_traffic()
        # Static files
        elif path == '/' or path == '/index.html':
            self.serve_file('index.html')
        elif path == '/device.html':
            self.serve_file('device.html')
        elif path.startswith('/network-devices.json') or path.startswith('/devices.json'):
            self.serve_file('network-devices.json')
        else:
            # Try to serve other static files
            self.serve_file(path.lstrip('/'))
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/api/traffic/start':
            self.handle_start_traffic()
        elif path == '/api/traffic/stop':
            self.handle_stop_traffic()
        elif path == '/api/scan':
            self.handle_scan_devices()
        else:
            self.send_response(404)
            self.end_headers()
    
    def load_traffic_summaries(self):
        """Load all traffic summaries from traffic_data folder"""
        summaries = {}
        traffic_dir = Path('traffic_data')
        
        # Try to load all_summaries.json first (faster)
        all_summaries_file = traffic_dir / 'all_summaries.json'
        if all_summaries_file.exists():
            try:
                with open(all_summaries_file, 'r') as f:
                    data = json.load(f)
                    # Handle both dict format {ip: summary} and list format
                    if isinstance(data, dict):
                        summaries = data
                    elif isinstance(data, list):
                        for summary in data:
                            if 'ip' in summary:
                                summaries[summary['ip']] = summary
                print(f"[+] Loaded {len(summaries)} traffic summaries from all_summaries.json")
            except Exception as e:
                print(f"[!] Error loading all_summaries.json: {e}")
                import traceback
                traceback.print_exc()
        
        # Fallback: load individual summary files if all_summaries.json is empty or doesn't exist
        if not summaries and traffic_dir.exists():
            for summary_file in traffic_dir.glob('summary_*.json'):
                try:
                    with open(summary_file, 'r') as f:
                        summary = json.load(f)
                        if 'ip' in summary:
                            summaries[summary['ip']] = summary
                except Exception as e:
                    print(f"[!] Error loading {summary_file}: {e}")
        
        return summaries
    
    def handle_get_device(self):
        """Get device information by IP"""
        query_params = parse_qs(urlparse(self.path).query)
        ip = query_params.get('ip', [None])[0]
        
        if not ip:
            self.send_json_response({'error': 'IP parameter required'}, 400)
            return
        
        # Load devices from JSON
        devices_file = 'network-devices.json'
        if not os.path.exists(devices_file):
            self.send_json_response({'error': 'Devices file not found'}, 404)
            return
        
        try:
            with open(devices_file, 'r') as f:
                data = json.load(f)
            
            # Handle both array and tree formats
            device_list = []
            if isinstance(data, list):
                device_list = data
            else:
                # Flatten tree structure
                def flatten_tree(node, result):
                    if isinstance(node, dict):
                        result.append(node)
                        if 'children' in node:
                            for child in node['children']:
                                flatten_tree(child, result)
                
                flatten_tree(data, device_list)
            
            # Find device by IP
            device = None
            for d in device_list:
                if d.get('ip') == ip:
                    device = d.copy()  # Make a copy to avoid modifying original
                    break
            
            if not device:
                self.send_json_response({'error': 'Device not found'}, 404)
                return
            
            # Load and merge traffic summary data
            traffic_summaries = self.load_traffic_summaries()
            device = self.merge_traffic_data(device, traffic_summaries)
            
            # Add additional traffic analysis data if available
            if ip in traffic_summaries:
                summary = traffic_summaries[ip]
                
                # Add protocol information
                if 'protocols' in summary:
                    device['protocols'] = summary['protocols']
                
                # Add conversations
                if 'conversations' in summary:
                    device['conversations'] = summary['conversations']
                
                # Add HTTP requests
                if 'http_requests' in summary and summary['http_requests']:
                    device['http_requests'] = summary['http_requests']
                
                # Add TLS SNI
                if 'tls_sni' in summary and summary['tls_sni']:
                    device['tls_sni'] = summary['tls_sni']
            else:
                # Ensure traffic stats are set even if not in summaries (set to 0)
                if 'packets' not in device:
                    device['packets'] = 0
                if 'bytes' not in device:
                    device['bytes'] = 0
                if 'upload_bps' not in device:
                    device['upload_bps'] = 0
                if 'download_bps' not in device:
                    device['download_bps'] = 0
                if 'traffic_stats' not in device:
                    device['traffic_stats'] = {
                        'packets': 0,
                        'bytes': 0,
                        'upload_bps': 0,
                        'download_bps': 0
                    }
            
            self.send_json_response(device)
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def merge_traffic_data(self, device, traffic_summaries):
        """Merge traffic summary data into a device object"""
        ip = device.get('ip')
        if ip and ip in traffic_summaries:
            summary = traffic_summaries[ip]
            
            # Merge device metadata from traffic summary (more detailed)
            if '_device_metadata' in summary:
                metadata = summary['_device_metadata']
                # Merge metadata, preferring traffic summary data
                for key, value in metadata.items():
                    if value is not None and value != '':
                        device[key] = value
            
            # Add ALL traffic statistics directly to device
            device['packets'] = summary.get('packets', 0)
            device['bytes'] = summary.get('bytes', 0)
            device['upload_bps'] = summary.get('upload_bps', 0)
            device['download_bps'] = summary.get('download_bps', 0)
            
            # Also keep in traffic_stats for backward compatibility
            device['traffic_stats'] = {
                'packets': summary.get('packets', 0),
                'bytes': summary.get('bytes', 0),
                'upload_bps': summary.get('upload_bps', 0),
                'download_bps': summary.get('download_bps', 0),
                'analyzed_at': summary.get('analyzed_at')
            }
        else:
            # Set default values if device not in summaries
            if 'packets' not in device:
                device['packets'] = 0
            if 'bytes' not in device:
                device['bytes'] = 0
            if 'upload_bps' not in device:
                device['upload_bps'] = 0
            if 'download_bps' not in device:
                device['download_bps'] = 0
            if 'traffic_stats' not in device:
                device['traffic_stats'] = {
                    'packets': 0,
                    'bytes': 0,
                    'upload_bps': 0,
                    'download_bps': 0
                }
        
        return device
    
    def handle_get_devices_with_traffic(self):
        """Get all devices with traffic data merged from all_summaries.json"""
        devices_file = 'network-devices.json'
        if not os.path.exists(devices_file):
            self.send_json_response({'error': 'Devices file not found'}, 404)
            return
        
        try:
            with open(devices_file, 'r') as f:
                data = json.load(f)
            
            # Load traffic summaries
            traffic_summaries = self.load_traffic_summaries()
            
            # Recursively merge traffic data into device tree
            def merge_tree(node):
                if isinstance(node, dict):
                    # Merge traffic data for this device
                    node = self.merge_traffic_data(node.copy(), traffic_summaries)
                    
                    # Recursively process children
                    if 'children' in node and isinstance(node['children'], list):
                        node['children'] = [merge_tree(child) for child in node['children']]
                
                return node
            
            # Handle both array and tree formats
            if isinstance(data, list):
                result = [merge_tree(device) for device in data]
            else:
                result = merge_tree(data)
            
            self.send_json_response(result)
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_start_traffic(self):
        """Start traffic capture for a device"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body)
            ip = data.get('ip')
            
            if not ip:
                self.send_json_response({'error': 'IP required'}, 400)
                return
            
            # Check if already capturing
            if ip in traffic_captures:
                self.send_json_response({'success': True, 'message': 'Already capturing'})
                return
            
            # Start background capture
            interface = os.environ.get('NETWORK_INTERFACE', 'en0')
            output_dir = Path('traffic_data')
            output_dir.mkdir(exist_ok=True)
            
            pcap_file = output_dir / f"live_{ip.replace('.', '_')}.pcap"
            
            # Start tshark in background (capturing continuously)
            # Using ring buffer to limit file size
            cmd = [
                'sudo', 'tshark',
                '-i', interface,
                '-f', f'host {ip}',
                '-w', str(pcap_file),
                '-b', 'filesize:10000',  # Rotate at 10MB
                '-b', 'files:2'  # Keep 2 files
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Initialize capture state
            traffic_captures[ip] = {
                'process': process,
                'pcap_file': str(pcap_file),
                'data': {
                    'ip': ip,
                    'packets': 0,
                    'bytes': 0,
                    'upload_bps': 0,
                    'download_bps': 0,
                    'recent_packets': []
                },
                'lock': threading.Lock(),
                'start_time': time.time()
            }
            
            # Start analysis thread
            analysis_thread = threading.Thread(
                target=self.analyze_traffic_loop,
                args=(ip,),
                daemon=True
            )
            analysis_thread.start()
            
            self.send_json_response({'success': True, 'message': 'Traffic capture started'})
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_stop_traffic(self):
        """Stop traffic capture for a device"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body)
            ip = data.get('ip')
            
            if ip in traffic_captures:
                capture = traffic_captures[ip]
                # Terminate tshark process
                if capture['process']:
                    capture['process'].terminate()
                    capture['process'].wait(timeout=5)
                del traffic_captures[ip]
                self.send_json_response({'success': True, 'message': 'Traffic capture stopped'})
            else:
                self.send_json_response({'success': True, 'message': 'No active capture'})
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)
    
    def parse_arp_scan_output(self, text):
        """Parse arp-scan output and return list of devices"""
        devices = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('Interface:') or line.startswith('Starting') or line.startswith('Ending'):
                continue
            
            # Try tab-separated format first: "IP\tMAC\tVendor"
            parts = line.split('\t')
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip()
                vendor = parts[2].strip() if len(parts) > 2 else ""
            else:
                # Try space-separated format: "IP MAC Vendor"
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip()
                    vendor = ' '.join(parts[2:]).strip() if len(parts) > 2 else ""
                else:
                    continue
            
            # Validate IP and MAC format
            ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
            mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
            
            if re.match(ip_pattern, ip) and re.match(mac_pattern, mac):
                # Normalize MAC address (convert to lowercase, use colons)
                mac = mac.lower().replace('-', ':')
                
                # Filter out broadcast and multicast addresses
                if not ip.endswith('.255') and not ip.endswith('.0') and \
                   not ip.startswith('224.') and not ip.startswith('239.'):
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor_hint": vendor
                    })
        
        return devices
    
    def get_network_range(self):
        """Get the local network range from interface"""
        try:
            # Try to get network info from ifconfig or ip command
            result = subprocess.run(["ifconfig", "en0"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Look for inet line: "inet 192.168.0.100 netmask 0xffffff00 broadcast 192.168.0.255"
                for line in result.stdout.splitlines():
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'inet' and i + 1 < len(parts):
                                ip = parts[i + 1]
                                ip_parts = ip.split('.')
                                if len(ip_parts) == 4:
                                    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except:
            pass
        return None
    
    def nmap_ping_sweep(self, network_range):
        """Use nmap to do a ping sweep of the network"""
        devices = []
        try:
            # Use nmap -sn (ping scan) with ARP scan to get MAC addresses
            # -PR uses ARP ping which is faster and gets MAC addresses
            cmd = ["sudo", "nmap", "-sn", "-PR", network_range]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                current_ip = None
                current_mac = None
                current_vendor = ""
                
                # Parse nmap output
                for line in result.stdout.splitlines():
                    # Look for "Nmap scan report for 192.168.0.100"
                    ip_match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        current_mac = None
                        current_vendor = ""
                    
                    # Look for MAC address: "MAC Address: AA:BB:CC:DD:EE:FF (Vendor)"
                    mac_match = re.search(r'MAC Address:\s+([0-9A-Fa-f:]{17})\s*(?:\(([^)]+)\))?', line, re.IGNORECASE)
                    if mac_match:
                        current_mac = mac_match.group(1).lower()
                        if len(mac_match.groups()) > 1 and mac_match.group(2):
                            current_vendor = mac_match.group(2)
                    
                    # When we have both IP and MAC, add the device
                    if current_ip and current_mac:
                        # Filter out invalid IPs
                        if not current_ip.endswith('.255') and not current_ip.endswith('.0') and \
                           not current_ip.startswith('224.') and not current_ip.startswith('239.'):
                            devices.append({
                                "ip": current_ip,
                                "mac": current_mac,
                                "vendor_hint": current_vendor
                            })
                            # Reset to avoid duplicates
                            current_ip = None
                            current_mac = None
                            current_vendor = ""
                    
                    # Also try to get MAC from ARP table if nmap didn't provide it
                    if current_ip and not current_mac:
                        try:
                            arp_result = subprocess.run(["arp", "-n", current_ip], capture_output=True, text=True, timeout=2)
                            if arp_result.returncode == 0:
                                mac_match = re.search(r'at\s+([0-9A-Fa-f:]{17})', arp_result.stdout)
                                if mac_match:
                                    current_mac = mac_match.group(1).lower()
                                    if current_ip and current_mac:
                                        devices.append({
                                            "ip": current_ip,
                                            "mac": current_mac,
                                            "vendor_hint": ""
                                        })
                                        current_ip = None
                                        current_mac = None
                        except:
                            pass
        except Exception as e:
            print(f"Error in nmap ping sweep: {e}")
        return devices
    
    def nmap_scan_ip_range(self, base_ip, start, end):
        """Scan a range of IPs using nmap to find devices and get MAC addresses"""
        devices = []
        try:
            # Build IP range string like "192.168.0.101-110"
            ip_parts = base_ip.split('.')
            if len(ip_parts) == 4:
                network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                ip_range = f"{network_base}.{start}-{end}"
                
                print(f"[+] Scanning IP range {ip_range} with nmap...")
                # Use nmap -sn -PR to do ARP ping scan and get MAC addresses
                cmd = ["sudo", "nmap", "-sn", "-PR", ip_range]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    current_ip = None
                    current_mac = None
                    current_vendor = ""
                    
                    # Parse nmap output
                    for line in result.stdout.splitlines():
                        # Look for "Nmap scan report for 192.168.0.101"
                        ip_match = re.search(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            current_ip = ip_match.group(1)
                            current_mac = None
                            current_vendor = ""
                        
                        # Look for MAC address: "MAC Address: AA:BB:CC:DD:EE:FF (Vendor)"
                        mac_match = re.search(r'MAC Address:\s+([0-9A-Fa-f:]{17})\s*(?:\(([^)]+)\))?', line, re.IGNORECASE)
                        if mac_match:
                            current_mac = mac_match.group(1).lower()
                            if len(mac_match.groups()) > 1 and mac_match.group(2):
                                current_vendor = mac_match.group(2)
                        
                        # When we have both IP and MAC, add the device
                        if current_ip and current_mac:
                            devices.append({
                                "ip": current_ip,
                                "mac": current_mac,
                                "vendor_hint": current_vendor
                            })
                            print(f"[+] Found device: {current_ip} ({current_mac})")
                            # Reset to avoid duplicates
                            current_ip = None
                            current_mac = None
                            current_vendor = ""
                        
                        # Also try to get MAC from ARP table if nmap found IP but no MAC
                        if current_ip and not current_mac:
                            try:
                                arp_result = subprocess.run(["arp", "-n", current_ip], capture_output=True, text=True, timeout=2)
                                if arp_result.returncode == 0:
                                    mac_match = re.search(r'at\s+([0-9A-Fa-f:]{17})', arp_result.stdout)
                                    if mac_match:
                                        current_mac = mac_match.group(1).lower()
                                        if current_ip and current_mac:
                                            devices.append({
                                                "ip": current_ip,
                                                "mac": current_mac,
                                                "vendor_hint": ""
                                            })
                                            print(f"[+] Found device (from ARP): {current_ip} ({current_mac})")
                                            current_ip = None
                                            current_mac = None
                            except:
                                pass
        except Exception as e:
            print(f"Error in nmap IP range scan: {e}")
        return devices
    
    def scan_devices_internal(self):
        """Internal method to scan devices (can be called without HTTP request)"""
        try:
            scanned_devices = []
            
            # Get the network base IP (e.g., 192.168.0.1)
            network_range = self.get_network_range()
            if not network_range:
                # Fallback: try to get from ifconfig
                try:
                    result = subprocess.run(["ifconfig", "en0"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if 'inet ' in line and '127.0.0.1' not in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part == 'inet' and i + 1 < len(parts):
                                        ip = parts[i + 1]
                                        network_range = ip.rsplit('.', 1)[0] + '.0/24'
                                        break
                except:
                    pass
            
            if network_range:
                # Extract base IP (e.g., "192.168.0" from "192.168.0.0/24")
                base_ip = network_range.split('/')[0]
                base_parts = base_ip.split('.')
                if len(base_parts) == 4:
                    base_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.1"
            
            # Scan multiple ranges: router (1), common range (101-110), and a few others
            scan_ranges = [
                (1, 1),      # Router at .1
                (100, 110),  # Common device range
                (2, 10),     # Early range
                (50, 60),    # Mid range
            ]
            
            for start, end in scan_ranges:
                devices = self.nmap_scan_ip_range(base_ip, start, end)
                # Add devices that aren't already found
                existing_ips = {d['ip'] for d in scanned_devices}
                for dev in devices:
                    if dev['ip'] not in existing_ips:
                        scanned_devices.append(dev)
            
            # Also check ARP table for any devices we might have missed
            try:
                arp_result = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
                if arp_result.returncode == 0:
                    existing_ips = {d['ip'] for d in scanned_devices}
                    for line in arp_result.stdout.splitlines():
                        match = re.search(r'\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})', line)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).lower()
                            if ip not in existing_ips and not ip.endswith('.255') and not ip.endswith('.0'):
                                scanned_devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "vendor_hint": ""
                                })
                                print(f"[+] ARP table found additional device: {ip}")
            except Exception as e:
                print(f"[!] ARP table check error: {e}")
            
            if not scanned_devices:
                print("[!] No devices found in scan")
                return False
            
            print(f"[+] Total devices found: {len(scanned_devices)}")
            
            # Load existing devices
            devices_file = 'network-devices.json'
            existing_devices = []
            if os.path.exists(devices_file):
                try:
                    with open(devices_file, 'r') as f:
                        existing_devices = json.load(f)
                        if not isinstance(existing_devices, list):
                            existing_devices = []
                except:
                    existing_devices = []
            
            # Create a map of existing devices by IP
            existing_by_ip = {d.get('ip'): d for d in existing_devices if d.get('ip')}
            
            # Merge scanned devices with existing devices
            # Keep existing device data (ports, OS, etc.) but update MAC/vendor if changed
            merged_devices = []
            seen_ips = set()
            
            # Add scanned devices (new or updated)
            for scanned in scanned_devices:
                ip = scanned['ip']
                seen_ips.add(ip)
                
                if ip in existing_by_ip:
                    # Update existing device with new MAC/vendor if changed
                    existing = existing_by_ip[ip].copy()
                    existing['mac'] = scanned['mac']
                    if scanned.get('vendor_hint'):
                        existing['vendor_hint'] = scanned['vendor_hint']
                    merged_devices.append(existing)
                else:
                    # New device - create basic entry
                    merged_devices.append({
                        "ip": ip,
                        "mac": scanned['mac'],
                        "vendor_hint": scanned.get('vendor_hint', ''),
                        "locally_admin": False,
                        "vendor_local": None,
                        "vendor_api": None,
                        "hostname": None,
                        "os_guess": None,
                        "ports": [],
                        "display_name": ip
                    })
            
            # Add existing devices that weren't in the scan (preserve them)
            for existing in existing_devices:
                ip = existing.get('ip')
                if ip and ip not in seen_ips:
                    merged_devices.append(existing)
            
            # Save merged devices
            with open(devices_file, 'w') as f:
                json.dump(merged_devices, f, indent=2)
            
            print(f"[+] Saved {len(merged_devices)} devices to network-devices.json")
            return True
            
        except subprocess.TimeoutExpired:
            print("[!] Scan timed out")
            return False
        except Exception as e:
            print(f"[!] Error during scan: {e}")
            return False
    
    def handle_scan_devices(self):
        """HTTP handler for scan endpoint"""
        try:
            scanned_devices = []
            
            # Get the network base IP (e.g., 192.168.0.1)
            network_range = self.get_network_range()
            if not network_range:
                # Fallback: try to get from ifconfig
                try:
                    result = subprocess.run(["ifconfig", "en0"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if 'inet ' in line and '127.0.0.1' not in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part == 'inet' and i + 1 < len(parts):
                                        ip = parts[i + 1]
                                        network_range = ip.rsplit('.', 1)[0] + '.0/24'
                                        break
                except:
                    pass
            
            if network_range:
                # Extract base IP (e.g., "192.168.0" from "192.168.0.0/24")
                base_ip = network_range.split('/')[0]
                base_parts = base_ip.split('.')
                if len(base_parts) == 4:
                    base_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.1"
            
            # Scan multiple ranges: router (1), common range (101-110), and a few others
            scan_ranges = [
                (1, 1),      # Router at .1
                (100, 110),  # Common device range
                (2, 10),     # Early range
                (50, 60),    # Mid range
            ]
            
            for start, end in scan_ranges:
                devices = self.nmap_scan_ip_range(base_ip, start, end)
                # Add devices that aren't already found
                existing_ips = {d['ip'] for d in scanned_devices}
                for dev in devices:
                    if dev['ip'] not in existing_ips:
                        scanned_devices.append(dev)
            
            # Also check ARP table for any devices we might have missed
            try:
                arp_result = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
                if arp_result.returncode == 0:
                    existing_ips = {d['ip'] for d in scanned_devices}
                    for line in arp_result.stdout.splitlines():
                        match = re.search(r'\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})', line)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).lower()
                            if ip not in existing_ips and not ip.endswith('.255') and not ip.endswith('.0'):
                                scanned_devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "vendor_hint": ""
                                })
                                print(f"[+] ARP table found additional device: {ip}")
            except Exception as e:
                print(f"[!] ARP table check error: {e}")
            
            if not scanned_devices:
                self.send_json_response({
                    'success': False,
                    'error': 'No devices found. Make sure you are on the network and devices are connected.'
                }, 400)
                return
            
            print(f"[+] Total devices found: {len(scanned_devices)}")
            
            # Load existing devices
            devices_file = 'network-devices.json'
            existing_devices = []
            if os.path.exists(devices_file):
                try:
                    with open(devices_file, 'r') as f:
                        existing_devices = json.load(f)
                        if not isinstance(existing_devices, list):
                            existing_devices = []
                except:
                    existing_devices = []
            
            # Create a map of existing devices by IP
            existing_by_ip = {d.get('ip'): d for d in existing_devices if d.get('ip')}
            
            # Merge scanned devices with existing devices
            # Keep existing device data (ports, OS, etc.) but update MAC/vendor if changed
            merged_devices = []
            seen_ips = set()
            
            # Add scanned devices (new or updated)
            for scanned in scanned_devices:
                ip = scanned['ip']
                seen_ips.add(ip)
                
                if ip in existing_by_ip:
                    # Update existing device with new MAC/vendor if changed
                    existing = existing_by_ip[ip].copy()
                    existing['mac'] = scanned['mac']
                    if scanned.get('vendor_hint'):
                        existing['vendor_hint'] = scanned['vendor_hint']
                    merged_devices.append(existing)
                else:
                    # New device - create basic entry
                    merged_devices.append({
                        "ip": ip,
                        "mac": scanned['mac'],
                        "vendor_hint": scanned.get('vendor_hint', ''),
                        "locally_admin": False,
                        "vendor_local": None,
                        "vendor_api": None,
                        "hostname": None,
                        "os_guess": None,
                        "ports": [],
                        "display_name": ip
                    })
            
            # Add existing devices that weren't in the scan (preserve them)
            for existing in existing_devices:
                ip = existing.get('ip')
                if ip and ip not in seen_ips:
                    merged_devices.append(existing)
            
            # Save merged devices
            with open(devices_file, 'w') as f:
                json.dump(merged_devices, f, indent=2)
            
            self.send_json_response({
                'success': True,
                'message': f'Found {len(scanned_devices)} devices, total {len(merged_devices)} devices',
                'scanned_count': len(scanned_devices),
                'total_count': len(merged_devices)
            })
            
        except subprocess.TimeoutExpired:
            self.send_json_response({'success': False, 'error': 'Scan timed out'}, 500)
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)
    
    def handle_get_traffic_data(self):
        """Get current traffic data for a device"""
        query_params = parse_qs(urlparse(self.path).query)
        ip = query_params.get('ip', [None])[0]
        
        if not ip:
            self.send_json_response({'error': 'IP parameter required'}, 400)
            return
        
        if ip not in traffic_captures:
            self.send_json_response({'error': 'No active capture for this device'}, 404)
            return
        
        capture = traffic_captures[ip]
        with capture['lock']:
            # Return a copy of the data
            data = capture['data'].copy()
        
        self.send_json_response(data)
    
    def analyze_traffic_loop(self, ip):
        """Background thread to continuously analyze captured traffic"""
        if ip not in traffic_captures:
            return
        
        capture = traffic_captures[ip]
        pcap_file = capture['pcap_file']
        last_packet_count = 0
        
        while ip in traffic_captures and capture['process'].poll() is None:
            try:
                time.sleep(10)  # Analyze every 10 seconds
                
                if not os.path.exists(pcap_file):
                    continue
                
                # Get recent packets using tshark
                # Read last 500 packets (more for 10 second window)
                cmd = f'tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len -e frame.protocols -c 500'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                
                if result.returncode != 0:
                    continue
                
                lines = result.stdout.strip().split('\n')
                if not lines or not lines[0]:
                    continue
                
                upload_bytes = 0
                download_bytes = 0
                recent_packets = []
                timestamps = []
                
                for line in lines:
                    parts = line.split('\t')
                    if len(parts) < 4:
                        continue
                    
                    try:
                        ts = float(parts[0])
                        src = parts[1] if len(parts) > 1 else ''
                        dst = parts[2] if len(parts) > 2 else ''
                        length = int(parts[3]) if len(parts) > 3 and parts[3] else 0
                        protocol = parts[4] if len(parts) > 4 else 'unknown'
                        
                        timestamps.append(ts)
                        
                        direction = None
                        if src == ip:
                            upload_bytes += length
                            direction = 'upload'
                        elif dst == ip:
                            download_bytes += length
                            direction = 'download'
                        
                        if direction:
                            recent_packets.append({
                                'timestamp': ts,
                                'direction': direction,
                                'size': length,
                                'protocol': protocol.split(':')[-1] if ':' in protocol else protocol
                            })
                    except (ValueError, IndexError):
                        continue
                
                # Calculate speeds (bps)
                duration = 10.0  # 10 second window
                if timestamps:
                    duration = max(timestamps) - min(timestamps)
                    duration = max(duration, 0.1)
                
                upload_bps = (upload_bytes * 8) / duration
                download_bps = (download_bytes * 8) / duration
                
                # Update capture data
                with capture['lock']:
                    capture['data']['packets'] = len(lines)
                    capture['data']['bytes'] = upload_bytes + download_bytes
                    capture['data']['upload_bps'] = upload_bps
                    capture['data']['download_bps'] = download_bps
                    # Keep only last 50 packets for display (more for 10 second updates)
                    capture['data']['recent_packets'] = recent_packets[-50:]
                
            except Exception as e:
                print(f"Error analyzing traffic for {ip}: {e}")
                time.sleep(10)  # Wait 10 seconds before retrying
    
    def serve_file(self, filename):
        """Serve a static file"""
        if filename == '':
            filename = 'index.html'
        
        filepath = Path(filename)
        if not filepath.exists() or not filepath.is_file():
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'File not found')
            return
        
        # Determine content type
        content_type = 'text/html'
        if filename.endswith('.json'):
            content_type = 'application/json'
        elif filename.endswith('.js'):
            content_type = 'application/javascript'
        elif filename.endswith('.css'):
            content_type = 'text/css'
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error reading file: {e}'.encode())
    
    def send_json_response(self, data, status=200):
        """Send JSON response"""
        json_data = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(json_data)))
        self.end_headers()
        self.wfile.write(json_data)
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        pass

def cleanup_captures():
    """Cleanup all active captures"""
    for ip, capture in list(traffic_captures.items()):
        try:
            if capture['process']:
                capture['process'].terminate()
        except:
            pass
    traffic_captures.clear()

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    cleanup_captures()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def run_startup_scan():
    """Run device scan at startup"""
    print("[+] Running initial device scan at startup...")
    try:
        # Create a temporary handler instance just to use the scan method
        # We need to pass valid arguments to BaseHTTPRequestHandler
        from io import BytesIO
        handler = NetworkRequestHandler(BytesIO(b''), ('127.0.0.1', 8000), None)
        handler.scan_devices_internal()
        print("[+] Initial device scan completed")
    except Exception as e:
        print(f"[!] Error during startup scan: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    os.chdir('.')
    
    # Run device scan at startup
    run_startup_scan()
    
    server = HTTPServer(('localhost', 8000), NetworkRequestHandler)
    print('Server running on http://localhost:8000')
    print('Note: Traffic capture requires sudo privileges for tshark')
    print('Set NETWORK_INTERFACE environment variable to specify interface (default: en0)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        cleanup_captures()
        server.shutdown()
