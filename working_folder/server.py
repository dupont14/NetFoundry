from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import subprocess
import threading
import time
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
                    summaries = json.load(f)
                return summaries
            except Exception as e:
                print(f"Error loading all_summaries.json: {e}")
        
        # Fallback: load individual summary files
        if traffic_dir.exists():
            for summary_file in traffic_dir.glob('summary_*.json'):
                try:
                    with open(summary_file, 'r') as f:
                        summary = json.load(f)
                        if 'ip' in summary:
                            summaries[summary['ip']] = summary
                except Exception as e:
                    print(f"Error loading {summary_file}: {e}")
        
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
                time.sleep(2)  # Analyze every 2 seconds
                
                if not os.path.exists(pcap_file):
                    continue
                
                # Get recent packets using tshark
                # Read last 100 packets
                cmd = f'tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len -e frame.protocols -c 100'
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
                duration = 2.0  # 2 second window
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
                    # Keep only last 20 packets for display
                    capture['data']['recent_packets'] = recent_packets[-20:]
                
            except Exception as e:
                print(f"Error analyzing traffic for {ip}: {e}")
                time.sleep(2)
    
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

if __name__ == '__main__':
    os.chdir('.')
    server = HTTPServer(('localhost', 8000), NetworkRequestHandler)
    print('Server running on http://localhost:8000')
    print('Note: Traffic capture requires sudo privileges for tshark')
    print('Set NETWORK_INTERFACE environment variable to specify interface (default: en0)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        cleanup_captures()
        server.shutdown()
