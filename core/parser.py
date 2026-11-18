"""Parse Nmap XML reports into plain dictionaries.

The parser uses :mod:`xml.etree.ElementTree` and matches elements by local
tag name, so a default XML namespace does not hide hosts or ports.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def parse_nmap_xml(xml_path: str | Path) -> list[dict[str, Any]]:
    """Extract hosts, names, and port states from an Nmap ``-oX`` report.

    Each host dictionary contains:

    - ``ip``: IPv4 or IPv6 address when Nmap recorded one.
    - ``mac``: MAC address when Nmap observed one (typical of ARP discovery).
    - ``hostnames``: resolved names, in the order Nmap emitted them.
    - ``status``: host state such as ``up`` or ``down``.
    - ``ports``: list of ``port``, ``protocol``, ``state``, ``service``,
      ``product``, ``version``, ``extrainfo``, and ``scripts``.
    - ``os_matches``: OS guesses from ``-O``, highest accuracy first.

    Args:
        xml_path: Path to an Nmap XML report.

    Returns:
        One dictionary per ``<host>`` element that has an address or a name.

    Raises:
        FileNotFoundError: The report does not exist.
        ValueError: The file is not well-formed XML.
    """
    path = Path(xml_path)
    if not path.is_file():
        raise FileNotFoundError(f"Nmap XML report not found: {path}")

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML report '{path}': {exc}") from exc

    hosts: list[dict[str, Any]] = []
    for host_node in _children(root, "host"):
        parsed = _parse_host(host_node)
        if parsed["ip"] or parsed["hostnames"]:
            hosts.append(parsed)
    return hosts


def _parse_host(host_node: ET.Element) -> dict[str, Any]:
    status_nodes = _children(host_node, "status")
    status = status_nodes[0].get("state", "unknown") if status_nodes else "unknown"

    ip = ""
    mac = ""
    for address in _children(host_node, "address"):
        addr_type = address.get("addrtype", "")
        addr = (address.get("addr") or "").strip()
        if addr_type in {"ipv4", "ipv6"} and addr and not ip:
            ip = addr
        elif addr_type == "mac" and addr and not mac:
            mac = addr

    hostnames: list[str] = []
    for hostnames_node in _children(host_node, "hostnames"):
        for hostname in _children(hostnames_node, "hostname"):
            name = (hostname.get("name") or "").strip()
            if name and name not in hostnames:
                hostnames.append(name)

    ports: list[dict[str, Any]] = []
    for ports_node in _children(host_node, "ports"):
        for port_node in _children(ports_node, "port"):
            ports.append(_parse_port(port_node))

    return {
        "ip": ip,
        "mac": mac,
        "hostnames": hostnames,
        "status": status,
        "os_matches": _parse_os(host_node),
        "ports": ports,
    }


def _parse_port(port_node: ET.Element) -> dict[str, Any]:
    state_nodes = _children(port_node, "state")
    service_nodes = _children(port_node, "service")
    port_id = (port_node.get("portid") or "").strip()
    service = product = version = extrainfo = ""
    if service_nodes:
        service_node = service_nodes[0]
        service = (service_node.get("name") or "").strip()
        product = (service_node.get("product") or "").strip()
        version = (service_node.get("version") or "").strip()
        extrainfo = (service_node.get("extrainfo") or "").strip()

    scripts: list[dict[str, str]] = []
    for script in _children(port_node, "script"):
        script_id = (script.get("id") or "").strip()
        output = (script.get("output") or "").strip()
        if len(output) > 4000:
            output = output[:4000] + "..."
        if script_id or output:
            scripts.append({"id": script_id, "output": output})

    return {
        "port": int(port_id) if port_id.isdigit() else port_id,
        "protocol": (port_node.get("protocol") or "").strip(),
        "state": state_nodes[0].get("state", "unknown") if state_nodes else "unknown",
        "service": service,
        "product": product,
        "version": version,
        "extrainfo": extrainfo,
        "scripts": scripts,
    }


def _parse_os(host_node: ET.Element) -> list[dict[str, Any]]:
    """Return OS guesses from ``-O``, highest accuracy first."""
    matches: list[dict[str, Any]] = []
    for os_node in _children(host_node, "os"):
        for match in _children(os_node, "osmatch"):
            name = (match.get("name") or "").strip()
            if not name:
                continue
            raw_accuracy = (match.get("accuracy") or "").strip()
            accuracy = int(raw_accuracy) if raw_accuracy.isdigit() else None
            matches.append({"name": name, "accuracy": accuracy})
    matches.sort(key=lambda item: -(item["accuracy"] or 0))
    return matches


def _children(parent: ET.Element, name: str) -> list[ET.Element]:
    """Return direct children whose local tag name matches ``name``."""
    return [child for child in list(parent) if _local_name(child.tag) == name]


def _local_name(tag: str) -> str:
    """Strip an XML namespace from a tag, leaving the local name."""
    return tag.rsplit("}", 1)[-1]
