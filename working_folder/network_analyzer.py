#!/usr/bin/env python3
"""
Network Traffic Analyzer
Reads devices from network-devices.json and captures/analyzes traffic for each device.
One JSON summary is written per IP plus an 'all_summaries.json' combined file.
"""
import argparse
import json
import subprocess
import os
import sys
from pathlib import Path
from datetime import datetime

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
        "tls_sni": [],
        "analyzed_at": datetime.utcnow().isoformat() + "Z"
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
        except Exception:
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
    try:
        proto_cmd = f'tshark -r {pcap_file} -q -z io,phs'
        proto_output = run(proto_cmd)
        summary["protocols"]["raw"] = proto_output
    except Exception as e:
        summary["protocols"]["error"] = str(e)

    # Conversations (TCP/UDP)
    try:
        conv_cmd = f'tshark -r {pcap_file} -q -z conv,tcp -z conv,udp'
        conv_output = run(conv_cmd)
        summary["conversations"].append(conv_output)
    except Exception as e:
        summary["conversations"].append(f"error: {e}")

    # HTTP requests
    try:
        http_cmd = f'tshark -r {pcap_file} -Y "http.request" -T fields -e http.host -e http.request.uri'
        http_output = run(http_cmd)
        summary["http_requests"] = [line.split('\t') for line in http_output.strip().splitlines() if line]
    except Exception as e:
        summary["http_requests"] = [f"error: {e}"]

    # TLS SNI
    try:
        tls_cmd = f'tshark -r {pcap_file} -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name'
        tls_output = run(tls_cmd)
        summary["tls_sni"] = list(set(line.strip() for line in tls_output.strip().splitlines() if line.strip()))
    except Exception as e:
        summary["tls_sni"] = [f"error: {e}"]

    return summary

def capture_traffic(interface, target_ip, duration, output_file):
    """Capture traffic for a specific IP."""
    cmd = f"sudo tshark -i {interface} -f 'host {target_ip}' -a duration:{duration} -w {output_file}"
    print(f"[+] Capturing traffic for {target_ip} for {duration}s -> {output_file}")
    subprocess.run(cmd, shell=True, check=True)

def load_devices(devices_file):
    """Load devices from network-devices.json (expects a list of dicts with 'ip')."""
    if not os.path.exists(devices_file):
        raise FileNotFoundError(f"Devices file not found: {devices_file}")
    with open(devices_file, 'r') as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Devices file must contain a JSON list of device objects (each with an 'ip' key).")
    return data

def analyze_all_devices(interface, devices_file, duration, output_dir):
    """Capture and analyze traffic for all devices listed in devices_file."""
    devices = load_devices(devices_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summaries = {}

    for device in devices:
        ip = device.get('ip')
        if not ip:
            print("[!] Skipping device entry without 'ip':", device)
            continue

        display = device.get('display_name') or device.get('name') or ip
        print(f"\n{'='*60}")
        print(f"Analyzing device: {display} ({ip})")
        print(f"{'='*60}")

        # Create unique pcap file for this device
        safe_ip = ip.replace('.', '_')
        pcap_file = output_dir / f"capture_{safe_ip}.pcap"

        try:
            # Capture traffic
            capture_traffic(interface, ip, duration, str(pcap_file))

            # Analyze captured traffic
            summary = analyze_pcap(str(pcap_file), ip)
            # Add metadata from device entry
            summary["_device_metadata"] = device
            summaries[ip] = summary

            # Save individual summary
            summary_file = output_dir / f"summary_{safe_ip}.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)

            print(f"[✓] Summary saved to {summary_file}")
            print(f"    Upload: {summary['upload_bps']:.2f} bps")
            print(f"    Download: {summary['download_bps']:.2f} bps")

        except subprocess.CalledProcessError as cpe:
            print(f"[✗] tshark failed for {ip}: {cpe}")
            summaries[ip] = {
                "ip": ip,
                "error": f"tshark failed: {cpe}",
                "packets": 0,
                "bytes": 0,
                "upload_bps": 0,
                "download_bps": 0
            }
        except Exception as e:
            print(f"[✗] Error analyzing {ip}: {e}")
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

    print(f"\n[+] All summaries saved to {combined_file}")
    return summaries

def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyze network traffic for all devices in network-devices.json"
    )
    parser.add_argument("--interface", required=True, help="Network interface to capture on (e.g., eth0, wlan0)")
    parser.add_argument("--devices", default="network-devices.json", help="Path to network devices JSON file (default: network-devices.json)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds per device (default: 10)")
    parser.add_argument("--output-dir", default="traffic_data", help="Directory to store capture files and summaries (default: traffic_data)")
    parser.add_argument("--ip", help="Analyze only a specific IP address instead of all devices (overrides devices file)")

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to capture traffic.")
        print("    Please run with sudo.")
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.ip:
        # Single IP analysis (keeps behavior if user wants single IP)
        print(f"[+] Analyzing single IP: {args.ip}")
        safe_ip = args.ip.replace('.', '_')
        pcap_file = output_dir / f"capture_{safe_ip}.pcap"
        capture_traffic(args.interface, args.ip, args.duration, str(pcap_file))
        summary = analyze_pcap(str(pcap_file), args.ip)

        summary_file = output_dir / f"summary_{safe_ip}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"[+] Summary saved to {summary_file}")
        print(json.dumps(summary, indent=2))
    else:
        # Analyze all devices from devices_file
        try:
            analyze_all_devices(
                args.interface,
                args.devices,
                args.duration,
                args.output_dir
            )
        except Exception as e:
            print(f"[!] Fatal error: {e}")
            sys.exit(2)

if __name__ == "__main__":
    main()

