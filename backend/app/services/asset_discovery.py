from __future__ import annotations

import ipaddress
import logging
import subprocess
from uuid import UUID
import xml.etree.ElementTree as ET

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality, AssetStatus, AssetType, AssetZone


logger = logging.getLogger("aegis.discovery")


class DiscoveryError(Exception):
    pass


def _get_local_networks() -> list[ipaddress.IPv4Network]:
    """Return the list of directly-connected IPv4 networks from `ip addr`."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, check=True, timeout=5,
        )
    except Exception:
        return []

    networks: list[ipaddress.IPv4Network] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            try:
                networks.append(ipaddress.IPv4Network(parts[1], strict=False))
            except (ValueError, IndexError):
                continue
    return networks


def _is_local_subnet(cidr: ipaddress.IPv4Network) -> bool:
    """Return True if the target CIDR overlaps a directly-connected network."""
    for local_net in _get_local_networks():
        if cidr.overlaps(local_net):
            return True
    return False


def _run_nmap_ping_scan(cidr: str, local: bool) -> str:
    """Run nmap host-discovery scan.

    For local (L2) subnets, a simple -sn (ARP-based) scan works well.
    For remote subnets, add TCP SYN + ACK probes so only hosts that
    genuinely respond to network probes are reported as up.
    """
    if local:
        command = ["nmap", "-sn", cidr, "-oX", "-"]
    else:
        # Remote subnet: use TCP SYN on port 22,80,443 + ARP fallback
        command = ["nmap", "-sn", "-PS22,80,443", "-PA80,443", cidr, "-oX", "-"]

    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=180)
    except FileNotFoundError as exc:
        raise DiscoveryError("nmap is not installed or not available in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError("nmap scan timed out") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise DiscoveryError(f"nmap scan failed: {stderr or 'unknown error'}") from exc
    return completed.stdout


def _parse_nmap_xml(xml_output: str) -> list[dict[str, str | None]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise DiscoveryError("Failed to parse nmap output") from exc

    devices: list[dict[str, str | None]] = []
    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state") if status_node is not None else "unknown"

        ip = None
        mac = None
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                ip = addr.get("addr")
            elif addr_type == "mac":
                mac = addr.get("addr")

        if not ip:
            continue

        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name")

        devices.append(
            {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "status": status,
            }
        )

    return devices


def _filter_real_hosts(devices: list[dict[str, str | None]], local: bool) -> list[dict[str, str | None]]:
    """Filter out phantom hosts.

    On virtualised host-only networks the hypervisor's virtual router
    answers ARP for every IP in the subnet, making nmap report hundreds
    of "up" hosts that are not real machines.  Real VMs always present a
    MAC address in the nmap output because they sit on the same Layer 2
    segment as the scanner.

    This filter only applies on **local** (directly connected) subnets.
    For remote subnets, nmap already uses TCP probes so phantom responses
    are not an issue — we keep all hosts that responded.
    """
    if not local:
        # Remote subnet — no phantom filtering needed.  All hosts that
        # responded to TCP probes are considered real.
        logger.info(
            "discovery_filter: remote subnet — keeping all %d responsive hosts",
            len(devices),
        )
        return devices

    # ── Local subnet: apply MAC-based phantom filter ─────────────────
    real: list[dict[str, str | None]] = []
    skipped = 0

    mac_hosts = [d for d in devices if d.get("mac")]
    no_mac_hosts = [d for d in devices if not d.get("mac")]

    for device in mac_hosts:
        real.append(device)

    # Among hosts without a MAC, keep at most the *one* that is the
    # scanner itself.  On a /24 host-only network we may see 200+
    # phantom entries; we only keep one if it looks like the local host.
    if len(no_mac_hosts) == 1:
        real.append(no_mac_hosts[0])
    elif no_mac_hosts:
        for device in no_mac_hosts:
            if device.get("hostname"):
                real.append(device)
            else:
                skipped += 1

    if skipped:
        logger.info(
            "discovery_filter: dropped %d phantom hosts without MAC addresses",
            skipped,
        )

    return real


def discover_assets(database: Session, owner_id: str, cidr: str) -> list[dict[str, str | None]]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise DiscoveryError("Invalid CIDR range") from exc

    local = _is_local_subnet(network)
    logger.info("discovery: scanning %s (local=%s)", str(network), local)

    xml_output = _run_nmap_ping_scan(str(network), local=local)
    raw_devices = _parse_nmap_xml(xml_output)

    # ── Filter out phantom hypervisor responses ──────────────────────────
    devices = _filter_real_hosts(raw_devices, local=local)
    logger.info(
        "discovery: %d raw hosts → %d real hosts on %s",
        len(raw_devices),
        len(devices),
        str(network),
    )

    owner_uuid = UUID(owner_id)
    for device in devices:
        ip = device["ip"]
        if ip is None:
            continue

        asset = (
            database.query(Asset)
            .filter(Asset.owner_id == owner_uuid, Asset.ip_address == ip)
            .first()
        )

        if asset is None:
            asset = Asset(
                owner_id=owner_uuid,
                name=device["hostname"] or ip,
                target=ip,
                ip_address=ip,
                hostname=device["hostname"],
                mac_address=device["mac"],
                discovery_status=device["status"] or "unknown",
                asset_type=AssetType.IP,
                status=AssetStatus.ACTIVE,
                criticality=AssetCriticality.MEDIUM,
                managed=False,
                asset_zone=AssetZone.UNKNOWN,
                topology_visible=False,
                attack_surface_enabled=False,
            )
            database.add(asset)
        else:
            asset.name = device["hostname"] or asset.name or ip
            asset.target = ip
            asset.hostname = device["hostname"]
            asset.mac_address = device["mac"]
            asset.discovery_status = device["status"] or "unknown"
            asset.status = AssetStatus.ACTIVE

    database.commit()
    return devices

