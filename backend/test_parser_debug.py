#!/usr/bin/env python3
"""Standalone parser validation script.

Runs nmap -sV against the target, captures XML, feeds it into
extract_structured_ports(), and prints every extracted field.

NO production code is modified. This is a temporary debug script.
"""
import json
import subprocess
import sys

# Add backend to path so we can import the parser directly
sys.path.insert(0, "/home/kali-attacker/digital_twin_project_v2/aegis-v2/backend")

from app.scanner.nmap_parser import extract_structured_ports

TARGET = "192.168.11.129"

print("=" * 70)
print(f"  PARSER VALIDATION: nmap -sV -oX - {TARGET}")
print("=" * 70)

# Step 1: Run nmap and capture raw XML
print("\n[STEP 1] Running nmap scan...")
try:
    result = subprocess.run(
        ["nmap", "-Pn", "-sV", "--version-light", "--top-ports", "200", "--open", "-oX", "-", TARGET],
        capture_output=True, text=True, timeout=120,
        stdin=subprocess.DEVNULL,
    )
    xml_output = result.stdout
except Exception as e:
    print(f"FATAL: nmap failed: {e}")
    sys.exit(1)

if not xml_output or "<nmaprun" not in xml_output:
    print(f"FATAL: No valid XML. stderr={result.stderr[:500]}")
    sys.exit(1)

print(f"  XML captured: {len(xml_output)} bytes")

# Step 2: Show raw XML snippet for first <port> block (evidence)
print("\n[STEP 2] RAW XML — first 3 <port> blocks:")
import xml.etree.ElementTree as ET
root = ET.fromstring(xml_output)
port_count = 0
for host in root.findall("host"):
    for port in host.findall("ports/port"):
        if port_count >= 3:
            break
        print(f"  --- port block {port_count + 1} ---")
        print(f"  {ET.tostring(port, encoding='unicode')[:400]}")
        port_count += 1

# Step 3: Feed XML into extract_structured_ports
print("\n[STEP 3] Calling extract_structured_ports()...")
parsed = extract_structured_ports(xml_output)

# Step 4: Print every extracted field per port
print("\n[STEP 4] EXTRACTED VALUES:")
print("-" * 70)

hosts = parsed.get("hosts", [])
if not hosts:
    print("  WARNING: No hosts found in parsed output!")
    sys.exit(1)

for hi, host in enumerate(hosts):
    print(f"\n  HOST {hi}: ip={host['ip']}  hostname={host['hostname']}  os={host.get('os_fingerprint')}")
    for pi, port_data in enumerate(host["ports"]):
        print(f"\n    PORT[{pi}]:")
        print(f"      port      = {port_data['port']}")
        print(f"      protocol  = {port_data['protocol']}")
        print(f"      service   = {port_data['service']}")
        print(f"      product   = {port_data['product']}")
        print(f"      version   = {port_data['version']}")
        print(f"      extrainfo = {port_data['extrainfo']}")
        print(f"      cpe_list  = {port_data['cpe_list']}")
        print(f"      script_output = {('yes (' + str(len(port_data['script_output'])) + ' chars)') if port_data['script_output'] else 'None'}")

# Step 5: Verification checklist
print("\n" + "=" * 70)
print("  VERIFICATION CHECKLIST")
print("=" * 70)
all_products = [p["product"] for h in hosts for p in h["ports"] if p["product"]]
all_services = [p["service"] for h in hosts for p in h["ports"] if p["service"]]
all_cpes     = [cpe for h in hosts for p in h["ports"] for cpe in p["cpe_list"]]

expected = ["vsftpd", "OpenSSH", "Apache", "Samba"]
for name in expected:
    found_in_product = any(name.lower() in (p or "").lower() for p in all_products)
    found_in_service = any(name.lower() in (s or "").lower() for s in all_services)
    found_in_cpe     = any(name.lower() in (c or "").lower() for c in all_cpes)
    status = "PASS" if (found_in_product or found_in_service or found_in_cpe) else "FAIL"
    print(f"  [{status}] {name:12s}  product={found_in_product}  service={found_in_service}  cpe={found_in_cpe}")

print(f"\n  Total ports extracted: {sum(len(h['ports']) for h in hosts)}")
print(f"  Total products found: {len(all_products)}")
print(f"  Total CPEs found:     {len(all_cpes)}")
print("=" * 70)
