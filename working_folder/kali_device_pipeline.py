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
from manuf import manuf
import requests
import xml.etree.ElementTree as ET

MANUF = manuf.MacParser()
MAC_API = "https://api.macvendors.com/"
ARP_SCAN_CMD = ["arp-scan", "--localnet"]
NMAP_PORTS = "22,80,135,139,445,3580,4000,1309"

def run_cmd(cmd, timeout=60):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError:
        return ""
    except subprocess.TimeoutExpired:
        return ""

def parse_arp_scan(text):
    devices = []
    for line in text.splitlines():
        m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.*)$", line)
        if m:
            ip, mac, vendor = m.groups()
            devices.append({"ip": ip, "mac": mac.lower(), "vendor_hint": vendor.strip()})
    return devices

def lookup_local_oui(mac):
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

def nmap_probe(ip):
    cmd = ["nmap", "-sV", "-O", "-Pn", "-p", NMAP_PORTS, "--script", "nbstat,smb-os-discovery", "-oX", "-", ip]
    out = run_cmd(cmd, timeout=90)
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

def main():
    print("[*] Running arp-scan...")
    arp_out = run_cmd(ARP_SCAN_CMD)
    if not arp_out or "Interface:" not in arp_out:
        print("[!] arp-scan failed, falling back to arp -an")
        arp_out = run_cmd(["arp", "-an"])
    devices = parse_arp_scan(arp_out)
    print(f"[*] Found {len(devices)} devices")

    results = []
    for d in devices:
        ip = d["ip"]
        mac = d["mac"]
        print(f"[*] Probing {ip} ({mac}) ...")
        entry = {"ip": ip, "mac": mac, "vendor_hint": d.get("vendor_hint","")}
        entry["locally_admin"] = is_locally_administered(mac)

        vendor_local = lookup_local_oui(mac)
        vendor_api = None if vendor_local else lookup_mac_api(mac)
        entry["vendor_local"] = vendor_local or None
        entry["vendor_api"] = vendor_api or None

        probe = nmap_probe(ip)
        entry["hostname"] = probe.get("hostname")
        entry["os_guess"] = probe.get("os")
        entry["ports"] = probe.get("ports", [])

        # fallback reverse DNS if hostname is None
        if not entry["hostname"]:
            try:
                entry["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                entry["hostname"] = None

        # friendly display name
        entry["display_name"] = make_display_name(entry["hostname"], entry["vendor_local"], ip, mac)

        results.append(entry)
        time.sleep(0.4)

    with open("network-devices.json","w") as f:
        json.dump(results, f, indent=2)
    print("[+] Wrote devices.json")

if __name__ == "__main__":
    main()

