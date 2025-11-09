#!/usr/bin/env python3
"""
Network Traffic Analyzer
Reads devices from network-devices.json and captures/analyzes traffic for each device.
"""
import argparse
import json
import subprocess
import os
import sys
import shutil
from pathlib import Path

def check_tshark():
    """Check if tshark is installed and available."""
    tshark_path = shutil.which('tshark')
    if not tshark_path:
        print("[!] ERROR: tshark is not installed or not in PATH")
        print("[!] Please install tshark (Wireshark) using one of the following:")
        print("[!]   macOS: brew install wireshark")
        print("[!]   Linux: sudo apt-get install tshark  (Debian/Ubuntu)")
        print("[!]          sudo yum install wireshark   (RHEL/CentOS)")
        sys.exit(1)
    return tshark_path

def run(cmd):
    """Run shell command and return stdout as string."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def analyze_pcap(pcap_file, target_ip):
    """
    Analyze the pcap file for a specific IP.
    Returns a dictionary with summary including upload/download speeds.
    """
    summary = {
        "ip": target_ip,
        "packets": 0,
        "bytes": 0,
        "upload_bps": 0,
        "download_bps": 0,
        "protocols": {},
        "conversations": [],
        "http_requests": [],
        "tls_sni": []
    }

    # Get frame time, src/dst IP, length
    tshark_cmd = f'tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len'
    output = run(tshark_cmd).strip()

    if not output:
        return summary

    upload_bytes = 0
    download_bytes = 0
    timestamps = []

    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) != 4:
            continue
        ts, src, dst, length = parts
        try:
            ts = float(ts)
            length = int(length)
        except:
            continue
        timestamps.append(ts)
        if src == target_ip:
            upload_bytes += length
        elif dst == target_ip:
            download_bytes += length

    # duration in seconds
    if timestamps:
        duration = max(timestamps) - min(timestamps)
        duration = max(duration, 1e-6)  # avoid division by zero
    else:
        duration = 1

    summary["upload_bps"] = upload_bytes * 8 / duration
    summary["download_bps"] = download_bytes * 8 / duration
    summary["packets"] = len(timestamps)
    summary["bytes"] = upload_bytes + download_bytes

    # Protocol summary
    proto_cmd = f'tshark -r {pcap_file} -q -z io,phs'
    proto_output = run(proto_cmd)
    summary["protocols"]["raw"] = proto_output

    # Conversations (TCP/UDP)
    conv_cmd = f'tshark -r {pcap_file} -q -z conv,tcp -z conv,udp'
    conv_output = run(conv_cmd)
    summary["conversations"].append(conv_output)

    # HTTP requests
    http_cmd = f'tshark -r {pcap_file} -Y "http.request" -T fields -e http.host -e http.request.uri'
    http_output = run(http_cmd)
    summary["http_requests"] = [line.split('\t') for line in http_output.strip().splitlines() if line]

    # TLS SNI
    tls_cmd = f'tshark -r {pcap_file} -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name'
    tls_output = run(tls_cmd)
    summary["tls_sni"] = list(set(line.strip() for line in tls_output.strip().splitlines() if line.strip()))

    return summary

def capture_traffic(interface, target_ip, duration, output_file):
    """Capture traffic for a specific IP."""
    cmd = f"sudo tshark -i {interface} -f 'host {target_ip}' -a duration:{duration} -w {output_file}"
    print(f"[+] Capturing traffic for {target_ip} for {duration}s...")
    subprocess.run(cmd, shell=True, check=True)

def load_devices(devices_file):
    """Load devices from network-devices.json"""
    with open(devices_file, 'r') as f:
        return json.load(f)

def analyze_all_devices(interface, devices_file, duration, output_dir):
    """Capture and analyze traffic for all devices in the network."""
    devices = load_devices(devices_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    if not devices or len(devices) == 0:
        print("[!] No devices found in network-devices.json")
        # Return empty summaries
        combined_file = output_dir / "all_summaries.json"
        with open(combined_file, 'w') as f:
            json.dump({}, f, indent=2)
        return {}
    
    # Get all device IPs
    device_ips = [d.get('ip') for d in devices if d.get('ip')]
    if not device_ips:
        print("[!] No valid device IPs found")
        return {}
    
    print(f"[+] Analyzing {len(device_ips)} devices: {', '.join(device_ips)}")
    
    # Create a single pcap file for all devices
    all_devices_pcap = output_dir / "capture_all_devices.pcap"
    
    # Build filter for all devices
    # Use subnet-based filter to capture all traffic on the network, then filter by device during analysis
    # This is more reliable than filtering by individual hosts
    first_ip_parts = device_ips[0].split('.')
    if len(first_ip_parts) == 4:
        # Use subnet filter to capture all traffic on the local network
        subnet_base = f"{first_ip_parts[0]}.{first_ip_parts[1]}.{first_ip_parts[2]}"
        host_filter = f"net {subnet_base}.0 mask 255.255.255.0"
        print(f"[+] Using subnet filter to capture all traffic on {subnet_base}.0/24")
    else:
        # Fallback to individual host filters if IP format is unexpected
        host_filter = " or ".join([f"host {ip}" for ip in device_ips])
        print(f"[+] Using individual host filters for {len(device_ips)} devices")
    
    summaries = {}
    
    try:
        # Capture traffic for all devices at once
        print(f"[+] Capturing traffic for all devices for {duration}s...")
        print(f"[+] Filter: {host_filter}")
        cmd = f"sudo tshark -i {interface} -f '{host_filter}' -a duration:{duration} -w {all_devices_pcap}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration+10)
        
        if result.returncode != 0:
            print(f"[!] Warning: tshark capture returned non-zero exit code: {result.returncode}")
            print(f"[!] stderr: {result.stderr}")
        
        # Check if pcap file was created and has content
        if not all_devices_pcap.exists():
            print(f"[✗] Error: Capture file was not created!")
            raise Exception("Capture file not created")
        
        file_size = all_devices_pcap.stat().st_size
        print(f"[+] Capture file size: {file_size} bytes")
        
        if file_size == 0:
            print(f"[!] Warning: Capture file is empty - no traffic captured")
        
        # Analyze captured traffic for each device
        for device in devices:
            ip = device.get('ip')
            if not ip:
                continue
                
            print(f"[*] Analyzing device: {device.get('display_name', ip)} ({ip})")
            
            try:
                # Extract packets for this specific device from the combined pcap
                device_pcap = output_dir / f"capture_{ip.replace('.', '_')}.pcap"
                extract_cmd = f"tshark -r {all_devices_pcap} -w {device_pcap} -Y 'ip.addr == {ip}'"
                result = subprocess.run(extract_cmd, shell=True, capture_output=True, timeout=10, text=True)
                
                # Check if extraction was successful and file exists
                if result.returncode != 0:
                    print(f"[!] Warning: Extraction failed for {ip}: {result.stderr}")
                
                # Analyze this device's traffic (even if extraction had issues, try to analyze)
                if device_pcap.exists() and device_pcap.stat().st_size > 0:
                    summary = analyze_pcap(str(device_pcap), ip)
                else:
                    # If no pcap file or empty, create empty summary
                    print(f"[!] No traffic captured for {ip} (file missing or empty)")
                    summary = {
                        "ip": ip,
                        "packets": 0,
                        "bytes": 0,
                        "upload_bps": 0,
                        "download_bps": 0,
                        "protocols": {},
                        "conversations": [],
                        "http_requests": [],
                        "tls_sni": []
                    }
                
                summaries[ip] = summary
                
                # Save individual summary
                summary_file = output_dir / f"summary_{ip.replace('.', '_')}.json"
                with open(summary_file, 'w') as f:
                    json.dump(summary, f, indent=2)
                
                if summary['packets'] > 0:
                    print(f"[✓] {ip}: {summary['packets']} packets, {summary['bytes']} bytes, {summary['upload_bps']:.2f}↑ {summary['download_bps']:.2f}↓ bps")
                else:
                    print(f"[○] {ip}: No traffic detected")
                
            except subprocess.TimeoutExpired:
                print(f"[✗] Timeout extracting traffic for {ip}")
                summaries[ip] = {
                    "ip": ip,
                    "error": "extraction_timeout",
                    "packets": 0,
                    "bytes": 0,
                    "upload_bps": 0,
                    "download_bps": 0
                }
            except Exception as e:
                print(f"[✗] Error analyzing {ip}: {e}")
                import traceback
                traceback.print_exc()
                summaries[ip] = {
                    "ip": ip,
                    "error": str(e),
                    "packets": 0,
                    "bytes": 0,
                    "upload_bps": 0,
                    "download_bps": 0
                }
        
        # Clean up combined pcap
        if all_devices_pcap.exists():
            all_devices_pcap.unlink()
            
    except Exception as e:
        print(f"[✗] Error capturing traffic: {e}")
        # Return empty summaries for all devices
        for device in devices:
            ip = device.get('ip')
            if ip:
                summaries[ip] = {
                    "ip": ip,
                    "error": str(e),
                    "packets": 0,
                    "bytes": 0,
                    "upload_bps": 0,
                    "download_bps": 0
                }
    
    # Save combined summaries
    combined_file = output_dir / "all_summaries.json"
    with open(combined_file, 'w') as f:
        json.dump(summaries, f, indent=2)
    
    print(f"[+] All summaries saved to {combined_file}")
    return summaries

def main():
    # Check for tshark first
    tshark_path = check_tshark()
    
    parser = argparse.ArgumentParser(
        description="Capture and analyze network traffic for all devices in network-devices.json"
    )
    parser.add_argument(
        "--interface", 
        required=True, 
        help="Network interface to capture on (e.g., eth0, wlan0, en0)"
    )
    parser.add_argument(
        "--devices", 
        default="network-devices.json",
        help="Path to network devices JSON file (default: network-devices.json)"
    )
    parser.add_argument(
        "--duration", 
        type=int, 
        default=10, 
        help="Capture duration in seconds per device (default: 10)"
    )
    parser.add_argument(
        "--output-dir",
        default="traffic_data",
        help="Directory to store capture files and summaries (default: traffic_data)"
    )
    parser.add_argument(
        "--ip",
        help="Analyze only a specific IP address instead of all devices"
    )
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to capture traffic.")
        print("    Please run with sudo.")
        sys.exit(1)
    
    if args.ip:
        # Single IP analysis
        print(f"[+] Analyzing single IP: {args.ip}")
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True)
        
        pcap_file = output_dir / f"capture_{args.ip.replace('.', '_')}.pcap"
        capture_traffic(args.interface, args.ip, args.duration, str(pcap_file))
        summary = analyze_pcap(str(pcap_file), args.ip)
        
        summary_file = output_dir / f"summary_{args.ip.replace('.', '_')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Summary saved to {summary_file}")
        print(json.dumps(summary, indent=2))
    else:
        # Analyze all devices
        analyze_all_devices(
            args.interface,
            args.devices,
            args.duration,
            args.output_dir
        )

if __name__ == "__main__":
    main()
