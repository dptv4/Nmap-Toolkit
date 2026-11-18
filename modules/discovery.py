"""Host discovery and fast TCP port scanning.

This is the first CPTS reconnaissance phase: find which addresses are up,
then sweep every TCP port on those hosts before a deeper enumeration.
Results are printed as a table and written to ``reports/`` as JSON (for the
next toolkit modules), XML (raw Nmap), and a short Markdown summary.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
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
    run_nmap,
)

console = Console()

# TCP ports used when ICMP is filtered. Matches the CPTS discovery set.
SYN_PING_PORTS = "21,22,80,443,445,3389"
DISCOVERY_METHODS = ("arp-icmp", "syn", "skip")
_LIST_SUFFIXES = {".txt", ".lst", ".list", ".csv"}
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_UNSAFE_TARGET = re.compile(r"[\s;|&$<>`(){}]")
_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class TargetError(ValueError):
    """The target is not an IP, CIDR range, hostname, or list file."""


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``discovery`` subcommand on the root CLI parser."""
    parser = subparsers.add_parser(
        "discovery",
        help="Discover live hosts and run a fast all-TCP-port scan",
        description=(
            "CPTS phase 1: host discovery (-sn) followed by a fast TCP sweep "
            "(-p- --min-rate 5000 -n) of every live host. "
            "Use only against lab ranges or networks you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py discovery -t 10.10.10.0/24 --method arp-icmp\n"
            "  python main.py discovery -t 10.10.10.10 --method syn\n"
            "  python main.py discovery -t 10.10.10.10 --method skip\n"
            "  python main.py discovery -t targets.txt --method syn --min-rate 5000\n"
        ),
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="IPv4/IPv6 address, CIDR range, hostname, or a file with one target per line",
    )
    parser.add_argument(
        "--method",
        choices=DISCOVERY_METHODS,
        default="arp-icmp",
        help=(
            "arp-icmp: ARP and ICMP echo (-sn -PE -PR); "
            f"syn: TCP SYN ping (-sn -PS{SYN_PING_PORTS}); "
            "skip: treat the target as up (-Pn)"
        ),
    )
    parser.add_argument(
        "--min-rate",
        type=int,
        default=5000,
        metavar="N",
        help="Minimum packet rate for the all-ports TCP sweep (default: 5000)",
    )
    parser.set_defaults(func=_from_args)


def run_discovery(target: str, method: str, min_rate: int = 5000) -> dict[str, Any]:
    """Discover live hosts and sweep all TCP ports on them.

    Args:
        target: Address, CIDR range, hostname, or path to a target list.
        method: ``arp-icmp``, ``syn``, or ``skip``.
        min_rate: Nmap ``--min-rate`` value for the port sweep. Defaults to
            5000, which is appropriate for a lab link, not a production WAN.

    Returns:
        The structured report that was also written under ``reports/``.
        ``hosts`` lists each live address and its open TCP ports so later
        modules can consume the JSON without parsing XML.

    Raises:
        TargetError: The target or method is not valid.
        NmapPrivilegeError: ARP/ICMP or SYN discovery was requested without
            administrator or root privileges.
    """
    if method not in DISCOVERY_METHODS:
        allowed = ", ".join(DISCOVERY_METHODS)
        raise TargetError(f"Unknown discovery method '{method}'. Choose one of: {allowed}.")
    if min_rate < 1:
        raise TargetError("--min-rate must be a positive integer.")

    target_args, label = load_target_args(target)
    reports_dir = ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    prefix = f"discovery_{label}_{stamp}"

    discovery_result: NmapRunResult | None = None
    discovered: list[dict[str, Any]] = []

    if method == "skip":
        console.print(
            "[bold]Host discovery skipped[/bold] (-Pn). The target is treated as up."
        )
        port_target_args = target_args
    else:
        _require_discovery_privileges(method)
        discovery_xml = reports_dir / f"{prefix}_hosts.xml"
        discovery_args = [*discovery_arguments(method), *target_args]
        console.print(f"[bold]Host discovery[/bold] ({method})")
        console.print(_format_command_preview(["nmap", *discovery_args]))
        discovery_result = run_nmap(discovery_args, discovery_xml)
        discovered = [
            host
            for host in parse_nmap_xml(discovery_xml)
            if host.get("status") == "up" and host.get("ip")
        ]
        _sort_hosts(discovered)
        console.print(f"[bold]{len(discovered)}[/bold] live host(s) found.")
        if not discovered:
            console.print(
                "[yellow]No live hosts responded. "
                "If the range drops ICMP, retry with --method syn. "
                "If you already know the host is up, retry with --method skip.[/yellow]"
            )
            report = _build_report(
                target=target,
                method=method,
                min_rate=min_rate,
                scan_type=None,
                hosts=[],
                discovery_result=discovery_result,
                ports_result=None,
                reports_dir=reports_dir,
                prefix=prefix,
            )
            json_path, markdown_path = _write_reports(report, reports_dir, prefix)
            console.print(f"JSON report: [cyan]{json_path}[/cyan]")
            console.print(f"Markdown summary: [cyan]{markdown_path}[/cyan]")
            return report
        port_target_args = _live_hosts_to_args(
            [str(host["ip"]) for host in discovered],
            reports_dir,
            prefix,
        )

    scan_type, scan_args = fast_scan_arguments(min_rate)
    if scan_type == "connect":
        console.print(
            "[yellow]Administrator privileges were not detected. "
            "The fast port scan will use a TCP connect scan (-sT) "
            f"instead of a SYN scan (-sS). {privilege_hint()}[/yellow]"
        )
    ports_xml = reports_dir / f"{prefix}_ports.xml"
    console.print(
        f"[bold]Fast TCP port scan[/bold] ({scan_type}, -p- --min-rate {min_rate} -n)"
    )
    console.print(_format_command_preview(["nmap", *scan_args, *port_target_args]))
    ports_result = run_nmap([*scan_args, *port_target_args], ports_xml)
    scanned = parse_nmap_xml(ports_xml)
    hosts = _merge_hosts(discovered, scanned)

    report = _build_report(
        target=target,
        method=method,
        min_rate=min_rate,
        scan_type=scan_type,
        hosts=hosts,
        discovery_result=discovery_result,
        ports_result=ports_result,
        reports_dir=reports_dir,
        prefix=prefix,
    )
    json_path, markdown_path = _write_reports(report, reports_dir, prefix)
    _print_results_table(hosts)
    console.print(f"\nJSON report: [cyan]{json_path}[/cyan]")
    console.print(f"Markdown summary: [cyan]{markdown_path}[/cyan]")
    console.print(f"Nmap XML: [cyan]{ports_xml}[/cyan]")
    return report


def load_target_args(target: str) -> tuple[list[str], str]:
    """Validate a CLI target and turn it into Nmap arguments.

    An existing file, or a missing path that looks like a list file, is
    treated as ``-iL``. Everything else must be an IP, a CIDR network, or a
    hostname. Values that start with ``-`` are rejected so a target cannot
    inject extra Nmap options.

    Returns:
        The Nmap target arguments and a filesystem-safe label used in
        report names.

    Raises:
        TargetError: The value is empty, unsafe, or not a supported target.
    """
    raw = target.strip()
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise TargetError("Target must be a non-empty single-line value.")
    if raw.startswith("-"):
        raise TargetError("Target must not start with '-'. Refusing option injection.")

    if _is_network(raw):
        return [raw], _safe_label(raw)
    if _looks_like_cidr(raw):
        raise TargetError(
            f"Invalid CIDR range '{raw}'. "
            "Use a prefix of 0-32 for IPv4 or 0-128 for IPv6."
        )

    path = Path(raw)
    if path.is_file():
        _validate_target_file(path)
        return ["-iL", str(path.resolve())], _safe_label(path.stem)

    if _looks_like_missing_file(raw, path):
        raise TargetError(f"Target list not found: {path}")

    if _UNSAFE_TARGET.search(raw):
        raise TargetError(
            "Target contains whitespace or shell metacharacters. "
            "Pass a single address, CIDR range, hostname, or a list file."
        )
    if _is_hostname(raw):
        return [raw], _safe_label(raw)

    raise TargetError(
        f"Invalid target '{target}'. Use an IPv4/IPv6 address, a CIDR range, "
        "a hostname, or a file with one target per line (.txt, .lst, .list, .csv)."
    )


def discovery_arguments(method: str) -> list[str]:
    """Return the Nmap options for one host-discovery method.

    ``arp-icmp`` sends an ICMP echo (``-PE``) and an ARP ping (``-PR``).
    ARP only elicits replies on the local L2 segment; ICMP still covers
    hosts reached through a route or a lab VPN. ``syn`` uses a TCP SYN ping
    against common service ports when ICMP is filtered. ``skip`` assumes
    the target is up.
    """
    if method == "arp-icmp":
        return ["-sn", "-PE", "-PR"]
    if method == "syn":
        return ["-sn", f"-PS{SYN_PING_PORTS}"]
    if method == "skip":
        return ["-Pn"]
    raise TargetError(f"Unknown discovery method '{method}'.")


def fast_scan_arguments(min_rate: int) -> tuple[str, list[str]]:
    """Return the scan type name and the fast all-ports TCP arguments.

    Privileged processes use a SYN scan (``-sS``). Otherwise the sweep falls
    back to a TCP connect scan (``-sT``), because ``-sS`` would fail without
    raw sockets. ``-Pn`` avoids a second discovery pass on hosts that were
    already found. The caller warns when the connect fallback is used.
    """
    if has_admin_privileges():
        scan_flag = "-sS"
        scan_type = "syn"
    else:
        scan_flag = "-sT"
        scan_type = "connect"
    return scan_type, [scan_flag, "-n", "-Pn", "-p-", "--min-rate", str(min_rate)]


def _from_args(args: argparse.Namespace) -> int:
    run_discovery(args.target, args.method, args.min_rate)
    return 0


def _require_discovery_privileges(method: str) -> None:
    if has_admin_privileges():
        return
    flags = "-PE -PR" if method == "arp-icmp" else f"-PS{SYN_PING_PORTS}"
    raise NmapPrivilegeError(
        f"Discovery method '{method}' uses {flags}, which needs raw sockets "
        f"and administrator or root privileges. {privilege_hint()} "
        "If the host is already known to be up, use --method skip."
    )


def _validate_target_file(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise TargetError(f"Could not read target list '{path}': {exc}") from exc

    entries = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        entries += 1
        if entry.startswith("-") or _UNSAFE_TARGET.search(entry):
            raise TargetError(
                f"Refusing unsafe target on line {line_number} of '{path}'."
            )
        if not _is_network(entry) and not _is_hostname(entry):
            raise TargetError(
                f"Invalid target on line {line_number} of '{path}': {entry}"
            )
    if entries == 0:
        raise TargetError(f"Target list '{path}' does not contain any hosts.")


def _looks_like_missing_file(raw: str, path: Path) -> bool:
    if path.suffix.lower() in _LIST_SUFFIXES:
        return True
    if raw.startswith(".") or "\\" in raw:
        return True
    # A slash that is not a CIDR (CIDR was already accepted) is a path.
    return "/" in raw


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _looks_like_cidr(value: str) -> bool:
    """Return whether ``value`` is an IP address plus a prefix, even if invalid.

    On Windows ``Path`` treats ``/`` as a separator, so an invalid prefix such
    as ``10.10.10.0/33`` must be rejected here instead of being reported as a
    missing target file.
    """
    head, separator, tail = value.partition("/")
    if not separator or not tail.isdigit():
        return False
    try:
        ipaddress.ip_address(head)
    except ValueError:
        return False
    return True


def _is_hostname(value: str) -> bool:
    return _HOSTNAME.fullmatch(value) is not None


def _safe_label(value: str) -> str:
    cleaned = _LABEL_UNSAFE.sub("_", value).strip("._")
    return cleaned[:80] or "target"


def _live_hosts_to_args(ips: list[str], reports_dir: Path, prefix: str) -> list[str]:
    """Pass live IPs on the command line, or via ``-iL`` when the line is long.

    Windows limits the command line to roughly 8191 characters. A large set
    of live hosts is written to a list file inside ``reports/`` instead.
    """
    if os.name == "nt" and sum(len(ip) + 1 for ip in ips) > 6000:
        list_path = reports_dir / f"{prefix}_live.txt"
        list_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
        return ["-iL", str(list_path)]
    return list(ips)


def _merge_hosts(
    discovered: list[dict[str, Any]],
    scanned: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Combine discovery names with open TCP ports from the fast sweep.

    The port scan runs with ``-n``, so hostnames found during discovery are
    copied onto the matching address. Only ports in state ``open`` are kept:
    that is the list the following modules need.
    """
    meta = {str(host.get("ip")): host for host in discovered if host.get("ip")}
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()

    for host in scanned:
        ip = str(host.get("ip") or "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        prior = meta.get(ip, {})
        hostnames = list(host.get("hostnames") or prior.get("hostnames") or [])
        mac = str(host.get("mac") or prior.get("mac") or "")
        merged.append(
            {
                "ip": ip,
                "mac": mac,
                "hostnames": hostnames,
                "status": host.get("status", "unknown"),
                "ports": _open_tcp_ports(host.get("ports") or []),
            }
        )

    for host in discovered:
        ip = str(host.get("ip") or "")
        if not ip or ip in seen:
            continue
        merged.append(
            {
                "ip": ip,
                "mac": str(host.get("mac") or ""),
                "hostnames": list(host.get("hostnames") or []),
                "status": host.get("status", "up"),
                "ports": [],
            }
        )

    _sort_hosts(merged)
    return merged


def _open_tcp_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    open_ports = [
        {
            "port": port.get("port"),
            "protocol": port.get("protocol", ""),
            "state": port.get("state", ""),
            "service": port.get("service", ""),
        }
        for port in ports
        if port.get("state") == "open" and port.get("protocol") == "tcp"
    ]
    open_ports.sort(key=lambda item: item["port"] if isinstance(item["port"], int) else 0)
    return open_ports


def _sort_hosts(hosts: list[dict[str, Any]]) -> None:
    def sort_key(host: dict[str, Any]) -> tuple[int, Any]:
        ip = str(host.get("ip") or "")
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    hosts.sort(key=sort_key)


def _build_report(
    target: str,
    method: str,
    min_rate: int,
    scan_type: str | None,
    hosts: list[dict[str, Any]],
    discovery_result: NmapRunResult | None,
    ports_result: NmapRunResult | None,
    reports_dir: Path,
    prefix: str,
) -> dict[str, Any]:
    artifacts: dict[str, str] = {
        "json": _relative(reports_dir / f"{prefix}.json"),
        "markdown": _relative(reports_dir / f"{prefix}.md"),
    }
    if discovery_result is not None:
        artifacts["hosts_xml"] = _relative(discovery_result.xml_path)
    if ports_result is not None:
        artifacts["ports_xml"] = _relative(ports_result.xml_path)

    commands: dict[str, list[str]] = {}
    if discovery_result is not None:
        commands["discovery"] = discovery_result.command
    if ports_result is not None:
        commands["ports"] = ports_result.command

    return {
        "module": "discovery",
        "target": target,
        "method": method,
        "min_rate": min_rate,
        "scan_type": scan_type,
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
    lines = [
        "# Discovery report",
        "",
        f"- Target: `{report['target']}`",
        f"- Method: `{report['method']}`",
        f"- Port scan: `{report['scan_type'] or 'not run'}`",
        f"- Min rate: {report['min_rate']}",
        f"- Generated: {report['generated_at']}",
        "",
        "## Live hosts",
        "",
    ]
    hosts: list[dict[str, Any]] = report["hosts"]
    if not hosts:
        lines.append("No live hosts were recorded.")
        lines.append("")
        return "\n".join(lines)

    for host in hosts:
        names = ", ".join(host.get("hostnames") or []) or "-"
        lines.append(f"### {host['ip']}")
        lines.append("")
        lines.append(f"- Status: {host.get('status', 'unknown')}")
        lines.append(f"- Hostnames: {names}")
        if host.get("mac"):
            lines.append(f"- MAC: {host['mac']}")
        ports = host.get("ports") or []
        if not ports:
            lines.append("- Open TCP ports: none")
        else:
            rendered = ", ".join(
                f"{port['port']}/{port['protocol']}"
                + (f" ({port['service']})" if port.get("service") else "")
                for port in ports
            )
            lines.append(f"- Open TCP ports: {rendered}")
        lines.append("")
    return "\n".join(lines)


def _print_results_table(hosts: list[dict[str, Any]]) -> None:
    table = Table(title="Live hosts and open TCP ports", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("Hostnames")
    if any(host.get("mac") for host in hosts):
        table.add_column("MAC", no_wrap=True)
    table.add_column("Open TCP ports", overflow="fold")

    open_port_total = 0
    hosts_with_ports = 0
    show_mac = any(host.get("mac") for host in hosts)
    for host in hosts:
        ports = host.get("ports") or []
        if ports:
            hosts_with_ports += 1
            open_port_total += len(ports)
        row = [
            str(host.get("ip") or ""),
            str(host.get("status") or ""),
            ", ".join(host.get("hostnames") or []) or "-",
        ]
        if show_mac:
            row.append(str(host.get("mac") or "-"))
        row.append(_format_ports(ports))
        table.add_row(*row)

    if hosts:
        console.print(table)
    else:
        console.print("[yellow]No live hosts to list.[/yellow]")
    console.print(
        f"Hosts: {len(hosts)} | With open ports: {hosts_with_ports} | "
        f"Open TCP ports: {open_port_total}"
    )


def _format_ports(ports: list[dict[str, Any]]) -> str:
    if not ports:
        return "none"
    labels: list[str] = []
    for port in ports:
        service = str(port.get("service") or "")
        label = f"{port.get('port')}/{port.get('protocol')}"
        if service and service not in {"unknown", "tcpwrapped"}:
            label = f"{label} ({service})"
        labels.append(label)
    return ", ".join(labels)


def _format_command_preview(command: list[str], limit: int = 10) -> str:
    if len(command) <= limit:
        return shlex.join(command)
    hidden = len(command) - limit
    return f"{shlex.join(command[:limit])} ... (+{hidden} more)"


def _relative(path: Path) -> str:
    root = Path(__file__).resolve().parent.parent
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path)
