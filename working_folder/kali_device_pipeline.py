#!/usr/bin/env python3
"""
kali_device_pipeline_with_names.py
Adds a friendly 'display_name' to each device.
"""

import re
import json
import subprocess
import time
import socket
import requests
import xml.etree.ElementTree as ET

# Try to import manuf, but make it optional
try:
    from manuf import manuf
    MANUF = manuf.MacParser()
except ImportError:
    print("[!] Warning: manuf module not found. Vendor lookup will be limited.")
    print("[!] Install with: pip3 install --user manuf")
    MANUF = None
MAC_API = "https://api.macvendors.com/"
ARP_SCAN_CMD = ["sudo", "arp-scan", "--interface=en0", "--localnet"]
NMAP_PORTS = "22,80,135,139,445,3580,4000,1309"

def run_cmd(cmd, timeout=60):
    try:
        # If cmd is a list and already has sudo, use it as-is
        # Otherwise, run it directly
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError:
        return ""
    except subprocess.TimeoutExpired:
        return ""

def parse_arp_scan(text):
    devices = []
    for line in text.splitlines():
        # Try arp-scan format first: "IP MAC vendor"
        m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.*)$", line)
        if m:
            ip, mac, vendor = m.groups()
            devices.append({"ip": ip, "mac": mac.lower(), "vendor_hint": vendor.strip()})
        else:
            # Try macOS arp -an format: "? (IP) at MAC on interface"
            m = re.search(r"\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})", line)
            if m:
                ip, mac = m.groups()
                # Filter out broadcast and multicast addresses, but allow .1 (router)
                if not ip.endswith('.255') and not ip.startswith('224.') and not ip.startswith('239.'):
                    devices.append({"ip": ip, "mac": mac.lower(), "vendor_hint": ""})
    return devices

def lookup_local_oui(mac):
    if MANUF is None:
        return None
    try:
        return MANUF.get_manuf(mac)
    except Exception:
        return None

def lookup_mac_api(mac):
    try:
        r = requests.get(MAC_API + mac, timeout=4)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except Exception:
        pass
    return None

def is_locally_administered(mac):
    try:
        first = int(mac.split(":")[0], 16)
        return bool(first & 0x02)
    except:
        return False

def nmap_probe(ip, quick=False):
    if quick:
        # Quick scan: just check if host is up and get basic info
        cmd = ["nmap", "-sn", "-Pn", ip]  # Ping scan only
        out = run_cmd(cmd, timeout=5)
        return {"hostname": None, "os": None, "ports": []}
    
    # Full scan with reduced timeout
    cmd = ["nmap", "-sV", "-O", "-Pn", "-p", NMAP_PORTS, "--script", "nbstat,smb-os-discovery", "-oX", "-", "--max-rtt-timeout", "500ms", "--host-timeout", "30s", ip]
    out = run_cmd(cmd, timeout=30)  # Reduced from 90 to 30 seconds
    if not out:
        return {"hostname": None, "os": None, "ports": []}

    try:
        root = ET.fromstring(out)
    except Exception:
        return {"hostname": None, "os": None, "ports": []}

    hostname = None
    os_guess = None
    ports = []

    for host in root.findall("host"):
        hn = host.find("hostnames")
        if hn is not None:
            hname_el = hn.find("hostname")
            if hname_el is not None and hname_el.get("name"):
                hostname = hname_el.get("name")

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                portid = port.get("portid")
                proto = port.get("protocol")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else None
                svc_el = port.find("service")
                svc = {}
                if svc_el is not None:
                    svc = {
                        "name": svc_el.get("name"),
                        "product": svc_el.get("product"),
                        "version": svc_el.get("version"),
                        "extrainfo": svc_el.get("extrainfo")
                    }
                ports.append({
                    "port": int(portid) if portid and portid.isdigit() else portid,
                    "proto": proto,
                    "state": state,
                    "service": svc
                })

        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                out_text = (script.get("output") or "") + "".join([ET.tostring(e, encoding="unicode", method="text") for e in script.findall("table")])
                # NetBIOS / SMB extraction
                m = re.search(r"NetBIOS name:\s*([^\s,;]+)", out_text, re.I)
                if m and not hostname:
                    hostname = m.group(1).strip()
                m2 = re.search(r"hostname:\s*([^\s,;]+)", out_text, re.I)
                if m2 and not hostname:
                    hostname = m2.group(1).strip()
                m3 = re.search(r"([A-Za-z0-9\-\_\.]{2,})\s*<00>", out_text)
                if m3 and not hostname:
                    hostname = m3.group(1).strip()

        os_el = host.find("os/osmatch")
        if os_el is not None:
            os_guess = os_el.get("name")

    if not hostname:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None

    return {"hostname": hostname, "os": os_guess, "ports": ports}

def make_display_name(hostname, vendor_local, ip, mac):
    """Friendly display name priority: hostname > vendor > IP"""
    if hostname:
        return hostname
    elif vendor_local:
        return vendor_local
    elif ip:
        return ip
    else:
        return mac

def find_router(devices):
    """Find the router (typically .1 address or default gateway) from the device list"""
    # Priority 1: Check for saved 192.168.0.1 (preferred target network)
    try:
        with open("network-devices.json", "r") as f:
            saved_devices = json.load(f)
            for device in saved_devices:
                ip = device.get("ip", "")
                if ip == "192.168.0.1":
                    print(f"[+] Using saved target router IP: {ip}")
                    return ip
    except:
        pass
    
    # Priority 2: Check for any saved router IP from previous scan
    try:
        with open("network-devices.json", "r") as f:
            saved_devices = json.load(f)
            for device in saved_devices:
                ip = device.get("ip", "")
                parts = ip.split('.')
                if len(parts) == 4 and parts[3] == '1':
                    print(f"[+] Using saved router IP: {ip}")
                    return ip
    except:
        pass
    
    # Priority 3: Look for router in current ARP scan (ending in .1)
    for d in devices:
        ip = d["ip"]
        parts = ip.split('.')
        if len(parts) == 4 and parts[3] == '1':
            print(f"[+] Found router in ARP table: {ip}")
            return ip
    
    # Priority 4: Try to get default gateway (but prefer 192.168.0.1 if we're scanning that network)
    try:
        # macOS/Linux: route get default
        route_cmd = ["route", "-n", "get", "default"]
        route_out = run_cmd(route_cmd, timeout=5)
        if route_out:
            # Look for gateway line
            for line in route_out.splitlines():
                if 'gateway' in line.lower():
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        gateway = match.group(1)
                        # If gateway is not 192.168.0.1, but we want to scan 192.168.0.x, use 192.168.0.1
                        if gateway != "192.168.0.1":
                            print(f"[!] Current gateway is {gateway}, but scanning target network 192.168.0.x")
                            return "192.168.0.1"
                        print(f"[+] Found default gateway: {gateway}")
                        return gateway
    except:
        pass
    
    # Priority 5: Default to 192.168.0.1 if nothing found
    print("[+] No router found, defaulting to target network 192.168.0.1")
    return "192.168.0.1"

def get_network_subnet(router_ip):
    """Extract network subnet from router IP (assumes /24)"""
    if not router_ip:
        return None
    parts = router_ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None

def filter_devices_by_subnet(devices, router_ip):
    """Filter devices to only those on the same subnet as the router"""
    if not router_ip:
        return devices
    
    router_parts = router_ip.split('.')
    if len(router_parts) != 4:
        return devices
    
    filtered = []
    for d in devices:
        ip = d["ip"]
        parts = ip.split('.')
        if len(parts) == 4:
            # Check if same subnet (first 3 octets match)
            if parts[0] == router_parts[0] and \
               parts[1] == router_parts[1] and \
               parts[2] == router_parts[2]:
                filtered.append(d)
    
    return filtered

def main():
    import sys
    # Check for quick mode (skip deep nmap scanning)
    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    
    print("[*] Running ARP scan to find devices...")
    arp_out = run_cmd(ARP_SCAN_CMD)
    if not arp_out or "Interface:" not in arp_out:
        print("[!] arp-scan failed, falling back to arp -an")
        arp_out = run_cmd(["arp", "-an"])
    all_devices = parse_arp_scan(arp_out)
    print(f"[*] Found {len(all_devices)} devices in ARP table")
    
    # If we found devices, print them for debugging
    if all_devices:
        print("[*] Devices in ARP table:")
        for d in all_devices:
            print(f"    - {d['ip']} ({d['mac']})")
    
    # Find the router
    router_ip = find_router(all_devices)
    if router_ip:
        print(f"[+] Target router: {router_ip}")
        network = get_network_subnet(router_ip)
        print(f"[+] Scanning network: {network}")
        router_parts = router_ip.split('.')
        network_prefix = f"{router_parts[0]}.{router_parts[1]}.{router_parts[2]}.x"
        
        # Filter to only devices on router's network from ARP
        devices = filter_devices_by_subnet(all_devices, router_ip)
        print(f"[*] Found {len(devices)} devices in ARP table on network ({network_prefix})")
        
        # If router is not in current ARP (we're not on that network), try to ping it
        router_in_arp = any(d["ip"] == router_ip for d in all_devices)
        if not router_in_arp:
            print(f"[*] Router {router_ip} not in ARP table")
            print(f"[*] Attempting to ping router to add to ARP table...")
            ping_result = run_cmd(["ping", "-c", "1", "-W", "1", router_ip], timeout=3)
            if ping_result:
                # Rescan ARP after ping
                arp_out = run_cmd(["arp", "-an"])
                new_devices = parse_arp_scan(arp_out)
                # Add router and any new devices on the network
                for d in new_devices:
                    if d["ip"] == router_ip or (d["ip"].startswith(router_parts[0] + "." + router_parts[1] + "." + router_parts[2] + ".")):
                        if not any(dev["ip"] == d["ip"] for dev in devices):
                            devices.append(d)
                            print(f"[+] Added {d['ip']} to device list")
            else:
                print(f"[!] Could not reach router {router_ip} - you may not be on this network")
        
        # Always include router in the device list if we found it
        router_in_list = any(d["ip"] == router_ip for d in devices)
        if not router_in_list:
            print(f"[+] Adding router {router_ip} to device list")
            # Try to get router MAC from ARP or existing data
            router_mac = None
            for d in all_devices:
                if d["ip"] == router_ip:
                    router_mac = d["mac"]
                    break
            if not router_mac:
                # Try to get from existing devices file
                try:
                    with open("network-devices.json", "r") as f:
                        existing = json.load(f)
                        for dev in existing:
                            if dev.get("ip") == router_ip:
                                router_mac = dev.get("mac")
                                break
                except:
                    pass
            
            if router_mac:
                devices.append({"ip": router_ip, "mac": router_mac, "vendor_hint": ""})
            else:
                # Ping router to add it to ARP table, then rescan
                print(f"[*] Pinging router to add to ARP table...")
                run_cmd(["ping", "-c", "1", "-W", "1", router_ip], timeout=3)
                # Rescan ARP
                arp_out = run_cmd(["arp", "-an"])
                new_devices = parse_arp_scan(arp_out)
                for d in new_devices:
                    if d["ip"] == router_ip:
                        devices.append(d)
                        break
        
        # Also include any devices from existing file that are on this network
        try:
            with open("network-devices.json", "r") as f:
                existing = json.load(f)
                for existing_dev in existing:
                    existing_ip = existing_dev.get("ip", "")
                    if existing_ip and existing_ip != router_ip:
                        # Check if on same network
                        existing_parts = existing_ip.split('.')
                        if len(existing_parts) == 4 and len(router_parts) == 4:
                            if existing_parts[0] == router_parts[0] and \
                               existing_parts[1] == router_parts[1] and \
                               existing_parts[2] == router_parts[2]:
                                # Check if not already in list
                                if not any(d["ip"] == existing_ip for d in devices):
                                    print(f"[+] Adding existing device {existing_ip} from previous scan")
                                    devices.append({
                                        "ip": existing_ip,
                                        "mac": existing_dev.get("mac", ""),
                                        "vendor_hint": existing_dev.get("vendor_hint", "")
                                    })
        except:
            pass
    else:
        print("[!] Router not found, scanning all devices")
        devices = all_devices

    # Load existing devices to preserve deep scan data
    existing_devices = {}
    try:
        with open("network-devices.json", "r") as f:
            existing = json.load(f)
            for dev in existing:
                existing_devices[dev["ip"]] = dev
    except:
        pass

    results = []
    for d in devices:
        ip = d["ip"]
        mac = d["mac"]
        
        # If device exists and we're in quick mode, reuse existing data
        if quick_mode and ip in existing_devices:
            print(f"[*] Reusing existing data for {ip} (quick mode)")
            existing = existing_devices[ip].copy()
            # Update MAC and vendor in case they changed
            existing["mac"] = mac
            existing["vendor_hint"] = d.get("vendor_hint", "")
            results.append(existing)
            continue
        
        print(f"[*] Probing {ip} ({mac}) ...")
        entry = {"ip": ip, "mac": mac, "vendor_hint": d.get("vendor_hint","")}
        entry["locally_admin"] = is_locally_administered(mac)
        
        vendor_local = lookup_local_oui(mac)
        vendor_api = None if vendor_local else lookup_mac_api(mac)
        entry["vendor_local"] = vendor_local or None
        entry["vendor_api"] = vendor_api or None
        
        # Only do deep nmap scan if not in quick mode or if device is new
        if not quick_mode or ip not in existing_devices:
            probe = nmap_probe(ip, quick=quick_mode)
            entry["hostname"] = probe.get("hostname")
            entry["os_guess"] = probe.get("os")
            entry["ports"] = probe.get("ports", [])
        else:
            # Reuse existing probe data
            existing = existing_devices[ip]
            entry["hostname"] = existing.get("hostname")
            entry["os_guess"] = existing.get("os_guess")
            entry["ports"] = existing.get("ports", [])
        
        # fallback reverse DNS if hostname is None
        if not entry["hostname"]:
            try:
                entry["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                entry["hostname"] = None
        
        # friendly display name
        entry["display_name"] = make_display_name(entry["hostname"], entry["vendor_local"], ip, mac)
        
        results.append(entry)
        if not quick_mode:
            time.sleep(0.4)  # Only sleep in full scan mode

    with open("network-devices.json","w") as f:
        json.dump(results, f, indent=2)
    print("[+] Wrote devices.json")

if __name__ == "__main__":
    main()

