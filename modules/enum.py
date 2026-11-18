"""Service and OS enumeration on top of a discovery report.

This is the second CPTS reconnaissance phase. It takes the live hosts and
open TCP ports from ``discovery`` (or a manual target) and runs a version
and default-script scan. OS detection (``-O``) is included when the process
is elevated. An optional UDP top-ports sweep is available with ``--udp``.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from core.parser import parse_nmap_xml
from core.runner import (
    NmapPrivilegeError,
    NmapRunResult,
    ensure_reports_dir,
    has_admin_privileges,
    privilege_hint,
    project_root,
    run_nmap,
)
from modules.discovery import TargetError, load_target_args

console = Console()

_PORT_TOKEN = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")
_UNSAFE = re.compile(r"[;|&$<>`(){}]")
_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_INTERESTING_UDP = frozenset({"open", "open|filtered"})
_SCRIPT_NOTE_LIMIT = 180


class EnumError(ValueError):
    """The enumeration input, ports, or discovery report is not usable."""


@dataclass
class EnumScope:
    """Targets selected for one enumeration run."""

    mode: str
    target: str
    label: str
    input_path: Path | None
    hosts: list[dict[str, Any]]
    target_args: list[str]
    port_spec: str
    udp: bool


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``enum`` subcommand on the root CLI parser."""
    parser = subparsers.add_parser(
        "enum",
        help="Enumerate service versions, default scripts, and OS guesses",
        description=(
            "CPTS phase 2: version detection, default NSE scripts, and OS "
            "detection (-sV -sC -O --version-intensity 5 -n -Pn) on the open "
            "TCP ports from discovery, or on a manual target. "
            "Use only against lab ranges or networks you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py enum --latest\n"
            "  python main.py enum --input reports/discovery_10.10.10.10_20261118T223300.json\n"
            "  python main.py enum -t 10.10.10.10 -p 22,80,445\n"
            "  python main.py enum --latest --udp\n"
        ),
    )
    parser.add_argument(
        "--input",
        help="Discovery JSON to enumerate (hosts and their open TCP ports)",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use the newest reports/discovery_*.json",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Manual target: IPv4/IPv6, CIDR, hostname, or a file with one target per line",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="TCP ports for manual mode, for example 22,80,443 or 1-1024",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Also run a fast UDP scan (-sU --top-ports 50 --min-rate 2000)",
    )
    parser.set_defaults(func=_from_args)


def run_enum(
    *,
    target: str | None = None,
    ports: str | None = None,
    input_path: str | None = None,
    latest: bool = False,
    udp: bool = False,
) -> dict[str, Any]:
    """Enumerate services on discovery results or on a manual target.

    Args:
        target: Address, CIDR, hostname, or target-list path. Manual mode.
        ports: TCP port spec used only with ``target``.
        input_path: Path to a discovery JSON report.
        latest: Select the newest ``reports/discovery_*.json``.
        udp: When true, also sweep the top 50 UDP ports. Requires elevation.

    Returns:
        The structured report written under ``reports/``.

    Raises:
        EnumError: The chosen inputs disagree or the discovery file is unusable.
        TargetError: A manual target is not an address, CIDR, hostname, or list.
        NmapPrivilegeError: ``--udp`` was requested without administrator or
            root privileges.
    """
    scope = resolve_scope(
        target=target,
        ports=ports,
        input_path=input_path,
        latest=latest,
        udp=udp,
    )
    if scope.udp:
        _require_udp_privileges()

    os_detection = has_admin_privileges()
    if not os_detection:
        console.print(
            "[yellow]Administrator privileges were not detected. "
            "OS detection (-O) needs raw sockets and will be skipped. "
            f"Version and default-script detection will still run. {privilege_hint()}[/yellow]"
        )

    reports_dir = ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    prefix = f"enum_{scope.label}_{stamp}"
    tcp_results: list[NmapRunResult] = []
    udp_result: NmapRunResult | None = None

    if _has_tcp_work(scope):
        console.print(f"[bold]TCP service enumeration[/bold] ({scope.target})")
        tcp_results = _run_tcp_scans(scope, reports_dir, prefix, os_detection)
    else:
        console.print(
            "[yellow]No open TCP ports to enumerate. "
            "The discovery hosts had no open TCP ports.[/yellow]"
        )

    if scope.udp and _has_udp_work(scope):
        console.print("[bold]UDP top-ports enumeration[/bold] (-sU --top-ports 50)")
        udp_result = _run_udp_scan(scope, reports_dir, prefix)
    elif scope.udp:
        console.print("[yellow]UDP scan skipped because the scope has no hosts.[/yellow]")

    tcp_hosts = _parse_results(tcp_results)
    udp_hosts = _parse_results([udp_result] if udp_result is not None else [])
    hosts = build_enum_hosts(scope.hosts, tcp_hosts, udp_hosts)
    report = _build_report(
        scope=scope,
        os_detection=os_detection,
        hosts=hosts,
        tcp_results=tcp_results,
        udp_result=udp_result,
        reports_dir=reports_dir,
        prefix=prefix,
    )
    json_path, markdown_path = _write_reports(report, reports_dir, prefix)
    _print_results_table(hosts, os_detection)
    console.print(f"\nJSON report: [cyan]{json_path}[/cyan]")
    console.print(f"Markdown summary: [cyan]{markdown_path}[/cyan]")
    for result in tcp_results:
        console.print(f"Nmap XML: [cyan]{result.xml_path}[/cyan]")
    if udp_result is not None:
        console.print(f"Nmap XML: [cyan]{udp_result.xml_path}[/cyan]")
    return report


def resolve_scope(
    *,
    target: str | None,
    ports: str | None,
    input_path: str | None,
    latest: bool,
    udp: bool,
) -> EnumScope:
    """Validate CLI inputs and describe what this run will scan.

    ``--input``, ``--latest``, and ``-t`` are mutually exclusive. Manual mode
    also requires ``-p``. Discovery mode reads open TCP ports from the JSON
    and rejects a manual port list.
    """
    chosen = [bool(input_path), bool(latest), bool(target)]
    if sum(chosen) != 1:
        raise EnumError(
            "Choose one source: --input <discovery.json>, --latest, or -t with -p."
        )
    if ports and not target:
        raise EnumError(
            "-p is only valid with -t. A discovery JSON already lists the open TCP ports."
        )
    if target and not ports:
        raise EnumError("Manual mode needs -p, for example -p 22,80,443.")

    if target:
        port_spec = normalize_port_spec(ports or "")
        target_args, label = load_target_args(target)
        return EnumScope(
            mode="manual",
            target=target,
            label=label,
            input_path=None,
            hosts=[],
            target_args=target_args,
            port_spec=port_spec,
            udp=udp,
        )

    path = find_latest_discovery(project_root() / "reports") if latest else Path(input_path or "")
    if not latest and not path.is_file():
        raise EnumError(f"Discovery JSON not found: {path}")
    discovered_target, hosts = load_discovery_hosts(path)
    return EnumScope(
        mode="discovery",
        target=discovered_target,
        label=_safe_label(discovered_target),
        input_path=path,
        hosts=hosts,
        target_args=[],
        port_spec="",
        udp=udp,
    )


def normalize_port_spec(spec: str) -> str:
    """Validate an Nmap TCP port list and return it in canonical form.

    Accepts comma-separated ports and ranges such as ``22,80,443`` or
    ``1-1024``. Spaces around commas are ignored. Anything that could be an
    extra Nmap option or a shell metacharacter is rejected.

    Raises:
        EnumError: The spec is empty or contains an invalid port.
    """
    raw = spec.strip()
    if not raw or "\n" in raw or "\r" in raw or "\x00" in raw or _UNSAFE.search(raw):
        raise EnumError(
            "Ports must be a list such as 22,80,443 or a range such as 1-1024."
        )
    normalized: list[str] = []
    for token in raw.split(","):
        piece = token.strip()
        match = _PORT_TOKEN.fullmatch(piece)
        if match is None:
            raise EnumError(f"Invalid port token '{piece}'. Use 22,80,443 or 1-1024.")
        start = int(match.group(1))
        end = int(match.group(2) or match.group(1))
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise EnumError(f"Port out of range in '{piece}'. Ports run from 1 to 65535.")
        normalized.append(piece if match.group(2) is None else f"{start}-{end}")
    if not normalized:
        raise EnumError("Provide at least one TCP port.")
    return ",".join(normalized)


def find_latest_discovery(reports_dir: Path) -> Path:
    """Return the newest ``discovery_*.json`` file in ``reports_dir``.

    Raises:
        EnumError: The directory is missing or contains no discovery report.
    """
    if not reports_dir.is_dir():
        raise EnumError(
            "No reports/ directory yet. Run discovery first, or pass -t and -p."
        )
    candidates = [path for path in reports_dir.glob("discovery_*.json") if path.is_file()]
    if not candidates:
        raise EnumError(
            f"No discovery JSON in {reports_dir}. Run discovery first, or pass -t and -p."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def load_discovery_hosts(path: Path) -> tuple[str, list[dict[str, Any]]]:
    """Read live hosts and open TCP ports from a discovery JSON file.

    Addresses are parsed with :mod:`ipaddress`, so a crafted report cannot
    inject extra Nmap arguments through the IP field.

    Returns:
        The original discovery target string and one dict per live host.

    Raises:
        EnumError: The file is missing, not JSON, or has an unexpected shape.
    """
    if not path.is_file():
        raise EnumError(f"Discovery JSON not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise EnumError(f"Could not read '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EnumError(f"Invalid JSON in '{path}': {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("hosts"), list):
        raise EnumError(
            f"'{path}' is not a discovery report. Expected an object with a hosts list."
        )

    module = payload.get("module")
    if module not in (None, "discovery"):
        console.print(
            "[yellow]Input JSON was not produced by discovery. "
            "Open TCP ports from its hosts list will be used anyway.[/yellow]"
        )

    target = str(payload.get("target") or path.stem)
    hosts: list[dict[str, Any]] = []
    for index, entry in enumerate(payload["hosts"], start=1):
        if not isinstance(entry, dict):
            raise EnumError(f"Host entry {index} in '{path}' is not an object.")
        status = str(entry.get("status") or "up")
        if status != "up":
            continue
        ip_raw = str(entry.get("ip") or "").strip()
        if not ip_raw:
            continue
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError as exc:
            raise EnumError(
                f"Host entry {index} in '{path}' has an invalid address '{ip_raw}'."
            ) from exc
        hostnames = [
            str(name)
            for name in (entry.get("hostnames") or [])
            if isinstance(name, str) and name.strip()
        ]
        hosts.append(
            {
                "ip": ip,
                "mac": str(entry.get("mac") or ""),
                "hostnames": hostnames,
                "status": status,
                "tcp_ports": _tcp_ports_from_entry(entry, path, index),
            }
        )
    return target, hosts


def tcp_scan_arguments(port_spec: str, *, os_detection: bool) -> list[str]:
    """Return the deep TCP enumeration arguments for one port spec.

    The flag set is ``-sV -sC -O --version-intensity 5 -n -Pn -p <ports>``.
    ``-O`` is omitted when ``os_detection`` is false because OS detection
    needs raw sockets. ``-n`` and ``-Pn`` skip DNS and a second discovery pass.
    """
    arguments = ["-sV", "-sC"]
    if os_detection:
        arguments.append("-O")
    arguments.extend(["--version-intensity", "5", "-n", "-Pn", "-p", port_spec])
    return arguments


def udp_scan_arguments() -> list[str]:
    """Return the fast UDP enumeration arguments.

    ``-n`` and ``-Pn`` match the TCP phase: no reverse DNS, and no second
    host-discovery pass against addresses already known to be up.
    """
    return ["-sU", "--top-ports", "50", "--min-rate", "2000", "-n", "-Pn"]


def build_enum_hosts(
    seeds: list[dict[str, Any]],
    tcp_hosts: list[dict[str, Any]],
    udp_hosts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge discovery metadata with TCP and UDP scan results.

    Hostnames and MAC addresses seen during discovery are kept, because the
    enumeration scans run with ``-n``. Only open TCP ports and UDP ports in
    state ``open`` or ``open|filtered`` are exported.
    """
    tcp_by_ip = {_ip_of(host): host for host in tcp_hosts if _ip_of(host)}
    udp_by_ip = {_ip_of(host): host for host in udp_hosts if _ip_of(host)}
    ordered: list[str] = []
    seed_by_ip: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        ip = str(seed.get("ip") or "")
        if not ip or ip in seed_by_ip:
            continue
        seed_by_ip[ip] = seed
        ordered.append(ip)
    for ip in [*tcp_by_ip, *udp_by_ip]:
        if ip not in seed_by_ip:
            ordered.append(ip)

    merged: list[dict[str, Any]] = []
    for ip in ordered:
        seed = seed_by_ip.get(ip, {})
        tcp = tcp_by_ip.get(ip, {})
        udp = udp_by_ip.get(ip, {})
        os_matches = list(tcp.get("os_matches") or [])
        best = os_matches[0] if os_matches else None
        ports = [
            *_public_ports(tcp.get("ports") or [], "tcp", frozenset({"open"})),
            *_public_ports(udp.get("ports") or [], "udp", _INTERESTING_UDP),
        ]
        ports.sort(key=lambda item: (item["protocol"], _port_sort_key(item["port"])))
        hostnames = list(tcp.get("hostnames") or seed.get("hostnames") or [])
        merged.append(
            {
                "ip": ip,
                "mac": str(tcp.get("mac") or udp.get("mac") or seed.get("mac") or ""),
                "hostnames": hostnames,
                "status": str(tcp.get("status") or udp.get("status") or seed.get("status") or "up"),
                "os": str(best["name"]) if best else "",
                "os_accuracy": best.get("accuracy") if best else None,
                "ports": ports,
            }
        )
    _sort_hosts(merged)
    return merged


def _from_args(args: argparse.Namespace) -> int:
    run_enum(
        target=args.target,
        ports=args.ports,
        input_path=args.input,
        latest=args.latest,
        udp=args.udp,
    )
    return 0


def _require_udp_privileges() -> None:
    if has_admin_privileges():
        return
    raise NmapPrivilegeError(
        "UDP enumeration uses -sU --top-ports 50, which needs raw sockets and "
        f"administrator or root privileges. {privilege_hint()}"
    )


def _tcp_ports_from_entry(entry: dict[str, Any], path: Path, index: int) -> list[int]:
    ports: list[int] = []
    raw_ports = entry.get("ports") or []
    if not isinstance(raw_ports, list):
        raise EnumError(f"Host entry {index} in '{path}' has an invalid ports list.")
    for port in raw_ports:
        if not isinstance(port, dict):
            raise EnumError(f"Host entry {index} in '{path}' has an invalid port object.")
        protocol = str(port.get("protocol") or "tcp")
        state = str(port.get("state") or "open")
        if protocol != "tcp" or state != "open":
            continue
        number = port.get("port")
        if isinstance(number, str) and number.isdigit():
            number = int(number)
        if not isinstance(number, int) or not 1 <= number <= 65535:
            raise EnumError(
                f"Host entry {index} in '{path}' has an invalid TCP port: {port.get('port')}"
            )
        if number not in ports:
            ports.append(number)
    ports.sort()
    return ports


def _has_tcp_work(scope: EnumScope) -> bool:
    if scope.mode == "manual":
        return True
    return any(host.get("tcp_ports") for host in scope.hosts)


def _has_udp_work(scope: EnumScope) -> bool:
    if scope.mode == "manual":
        return True
    return any(host.get("ip") for host in scope.hosts)


def _run_tcp_scans(
    scope: EnumScope,
    reports_dir: Path,
    prefix: str,
    os_detection: bool,
) -> list[NmapRunResult]:
    jobs: list[tuple[str, list[str]]] = []
    if scope.mode == "manual":
        jobs.append((scope.port_spec, scope.target_args))
    else:
        for index, (port_spec, hosts) in enumerate(_group_hosts_by_ports(scope.hosts).items(), start=1):
            ips = [str(host["ip"]) for host in hosts]
            jobs.append((port_spec, _targets_to_args(ips, reports_dir, f"{prefix}_tcp{index}")))

    results: list[NmapRunResult] = []
    width = len(str(len(jobs)))
    for index, (port_spec, target_args) in enumerate(jobs, start=1):
        suffix = "_tcp.xml" if len(jobs) == 1 else f"_tcp_{index:0{width}d}.xml"
        xml_path = reports_dir / f"{prefix}{suffix}"
        arguments = [*tcp_scan_arguments(port_spec, os_detection=os_detection), *target_args]
        console.print(_format_command_preview(["nmap", *arguments]))
        results.append(run_nmap(arguments, xml_path))
    return results


def _run_udp_scan(scope: EnumScope, reports_dir: Path, prefix: str) -> NmapRunResult:
    if scope.mode == "manual":
        target_args = scope.target_args
    else:
        target_args = _targets_to_args(
            [str(host["ip"]) for host in scope.hosts if host.get("ip")],
            reports_dir,
            f"{prefix}_udp",
        )
    arguments = [*udp_scan_arguments(), *target_args]
    console.print(_format_command_preview(["nmap", *arguments]))
    return run_nmap(arguments, reports_dir / f"{prefix}_udp.xml")


def _group_hosts_by_ports(hosts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for host in hosts:
        ports = [int(port) for port in host.get("tcp_ports") or []]
        if not ports:
            continue
        spec = ",".join(str(port) for port in ports)
        grouped.setdefault(spec, []).append(host)
    return grouped


def _targets_to_args(ips: list[str], reports_dir: Path, prefix: str) -> list[str]:
    """Pass addresses on the command line, or via ``-iL`` when the line is long."""
    if os.name == "nt" and sum(len(ip) + 1 for ip in ips) > 6000:
        list_path = reports_dir / f"{prefix}_targets.txt"
        list_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
        return ["-iL", str(list_path)]
    return list(ips)


def _parse_results(results: list[NmapRunResult]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for result in results:
        parsed.extend(parse_nmap_xml(result.xml_path))
    return parsed


def _public_ports(
    ports: list[dict[str, Any]],
    protocol: str,
    states: frozenset[str],
) -> list[dict[str, Any]]:
    exported: list[dict[str, Any]] = []
    for port in ports:
        if port.get("protocol") != protocol or port.get("state") not in states:
            continue
        scripts = [
            {"id": str(script.get("id") or ""), "output": str(script.get("output") or "")}
            for script in (port.get("scripts") or [])
            if isinstance(script, dict)
        ]
        exported.append(
            {
                "port": port.get("port"),
                "protocol": protocol,
                "state": port.get("state", ""),
                "service": port.get("service", ""),
                "product": port.get("product", ""),
                "version": port.get("version", ""),
                "extrainfo": port.get("extrainfo", ""),
                "scripts": scripts,
            }
        )
    return exported


def _build_report(
    *,
    scope: EnumScope,
    os_detection: bool,
    hosts: list[dict[str, Any]],
    tcp_results: list[NmapRunResult],
    udp_result: NmapRunResult | None,
    reports_dir: Path,
    prefix: str,
) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        "json": _relative(reports_dir / f"{prefix}.json"),
        "markdown": _relative(reports_dir / f"{prefix}.md"),
        "tcp_xml": [_relative(result.xml_path) for result in tcp_results],
    }
    if udp_result is not None:
        artifacts["udp_xml"] = _relative(udp_result.xml_path)
    commands: dict[str, Any] = {
        "tcp": [result.command for result in tcp_results],
    }
    if udp_result is not None:
        commands["udp"] = udp_result.command
    return {
        "module": "enum",
        "source": scope.mode,
        "input": _relative(scope.input_path) if scope.input_path else None,
        "target": scope.target,
        "os_detection": os_detection,
        "udp": scope.udp and udp_result is not None,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hosts": hosts,
        "artifacts": artifacts,
        "commands": commands,
    }


def _write_reports(
    report: dict[str, Any],
    reports_dir: Path,
    prefix: str,
) -> tuple[Path, Path]:
    json_path = reports_dir / f"{prefix}.json"
    markdown_path = reports_dir / f"{prefix}.md"
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def _render_markdown(report: dict[str, Any]) -> str:
    source = report.get("input") or "manual"
    lines = [
        "# Service enumeration",
        "",
        f"- Target: `{report['target']}`",
        f"- Source: `{source}`",
        f"- OS detection: {'yes' if report['os_detection'] else 'skipped (no administrator/root)'}",
        f"- UDP top 50: {'yes' if report['udp'] else 'no'}",
        f"- Generated: {report['generated_at']}",
        "",
    ]
    hosts: list[dict[str, Any]] = report["hosts"]
    if not hosts:
        lines.extend(["No hosts were enumerated.", ""])
        return "\n".join(lines)

    for host in hosts:
        names = ", ".join(host.get("hostnames") or [])
        title = f"## {host['ip']}" + (f" ({names})" if names else "")
        lines.extend([title, "", f"- OS: {_format_os(host, report['os_detection'])}"])
        if host.get("mac"):
            lines.append(f"- MAC: {host['mac']}")
        ports = host.get("ports") or []
        if not ports:
            lines.append("- Open services: none")
            lines.append("")
            continue
        lines.append("- Services:")
        for port in ports:
            lines.append(
                f"  - {port['port']}/{port['protocol']} {port['state']} — "
                f"{port.get('service') or 'unknown'} — {_format_version(port)}"
            )
            for script in port.get("scripts") or []:
                note = _script_note(str(script.get("output") or ""))
                if note:
                    lines.append(f"    - `{script.get('id') or 'script'}`: {note}")
        lines.append("")
    return "\n".join(lines)


def _print_results_table(hosts: list[dict[str, Any]], os_detection: bool) -> None:
    table = Table(title="Service enumeration", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", no_wrap=True)
    table.add_column("Service")
    table.add_column("Version", overflow="fold")
    table.add_column("OS", overflow="fold")

    service_count = 0
    os_count = 0
    for host in hosts:
        os_text = _format_os(host, os_detection)
        if host.get("os"):
            os_count += 1
        ports = host.get("ports") or []
        if not ports:
            table.add_row(str(host.get("ip") or ""), "-", "-", "-", os_text)
            continue
        for port in ports:
            service_count += 1
            table.add_row(
                str(host.get("ip") or ""),
                f"{port.get('port')}/{port.get('protocol')}",
                str(port.get("service") or "-"),
                _format_version(port),
                os_text,
            )
    if hosts:
        console.print(table)
    else:
        console.print("[yellow]No hosts to list.[/yellow]")
    console.print(
        f"Hosts: {len(hosts)} | Services: {service_count} | OS guesses: {os_count}"
    )


def _format_version(port: dict[str, Any]) -> str:
    parts = [str(port.get(key) or "").strip() for key in ("product", "version", "extrainfo")]
    text = " ".join(part for part in parts if part)
    return text or "-"


def _format_os(host: dict[str, Any], os_detection: bool) -> str:
    name = str(host.get("os") or "").strip()
    if not name:
        return "n/a" if os_detection else "not run"
    accuracy = host.get("os_accuracy")
    if isinstance(accuracy, int):
        return f"{name} ({accuracy}%)"
    return name


def _script_note(output: str) -> str:
    first = output.replace("\r", " ").replace("\n", " ").strip()
    if not first:
        return ""
    if len(first) > _SCRIPT_NOTE_LIMIT:
        return first[: _SCRIPT_NOTE_LIMIT - 3] + "..."
    return first


def _format_command_preview(command: list[str], limit: int = 12) -> str:
    if len(command) <= limit:
        return shlex.join(command)
    hidden = len(command) - limit
    return f"{shlex.join(command[:limit])} ... (+{hidden} more)"


def _safe_label(value: str) -> str:
    cleaned = _LABEL_UNSAFE.sub("_", value).strip("._")
    return cleaned[:80] or "target"


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root()).as_posix()
    except ValueError:
        return str(path)


def _ip_of(host: dict[str, Any]) -> str:
    return str(host.get("ip") or "")


def _port_sort_key(port: Any) -> tuple[int, int | str]:
    if isinstance(port, int):
        return (0, port)
    return (1, str(port))


def _sort_hosts(hosts: list[dict[str, Any]]) -> None:
    def sort_key(host: dict[str, Any]) -> tuple[int, Any]:
        ip = str(host.get("ip") or "")
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    hosts.sort(key=sort_key)
