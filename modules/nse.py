"""Targeted NSE scripts for the services found by discovery or enum.

The module maps open ports and service names to a small CPTS script set and
runs only those scripts on those ports. It does not launch the full NSE
catalog. ``--vuln`` is opt-in. UDP scripts (SNMP, and DNS when the report
says the port is UDP) need administrator or root privileges.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape

from core.parser import parse_nmap_xml
from core.runner import (
    NmapNotFoundError,
    NmapRunResult,
    ensure_reports_dir,
    has_admin_privileges,
    nmap_binary,
    privilege_hint,
    project_root,
    run_nmap,
)
from modules.discovery import load_target_args
from modules.enum import EnumError, normalize_port_spec

console = Console()

_SCRIPT_TOKEN = re.compile(r"^[A-Za-z0-9_.*+-]+$")
_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_INTERESTING_STATES = frozenset({"open", "open|filtered"})
_CONSOLE_LINES = 40
_MAX_CUSTOM_PORTS = 128


class NseError(ValueError):
    """The NSE input, script list, or report is not usable."""


@dataclass(frozen=True)
class ScriptFamily:
    """Ports and service names that select one NSE script group."""

    ports: frozenset[int]
    protocols: frozenset[str]
    services: frozenset[str]
    scripts: tuple[str, ...]


# Kerberos and LDAP are split so port 88 does not run LDAP scripts and
# port 389 does not run the Kerberos script.
_FAMILIES: tuple[ScriptFamily, ...] = (
    ScriptFamily(
        ports=frozenset({80, 443, 8080, 8443}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"http", "https", "http-alt", "http-proxy", "https-alt", "ssl/http", "ssl/https"}),
        scripts=("http-title", "http-headers", "http-methods", "http-robots.txt", "http-enum"),
    ),
    ScriptFamily(
        ports=frozenset({139, 445}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"smb", "microsoft-ds", "netbios-ssn", "samba"}),
        scripts=("smb-os-discovery", "smb-enum-shares", "smb-enum-users", "smb-protocols"),
    ),
    ScriptFamily(
        ports=frozenset({21}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"ftp"}),
        scripts=("ftp-anon", "ftp-syst", "ftp-bounce"),
    ),
    ScriptFamily(
        ports=frozenset({22}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"ssh"}),
        scripts=("ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods"),
    ),
    ScriptFamily(
        ports=frozenset({53}),
        protocols=frozenset({"tcp", "udp"}),
        services=frozenset({"domain", "dns"}),
        scripts=("dns-nsid", "dns-recursion", "dns-zone-transfer"),
    ),
    ScriptFamily(
        ports=frozenset({161}),
        protocols=frozenset({"udp"}),
        services=frozenset({"snmp"}),
        scripts=("snmp-info", "snmp-sysdescr", "snmp-interfaces"),
    ),
    ScriptFamily(
        ports=frozenset({88}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"kerberos", "kerberos-sec"}),
        scripts=("krb5-enum-users",),
    ),
    ScriptFamily(
        ports=frozenset({389}),
        protocols=frozenset({"tcp"}),
        services=frozenset({"ldap"}),
        scripts=("ldap-rootdse", "ldap-search"),
    ),
)

_MANUAL_TCP_PORTS = frozenset(
    port for family in _FAMILIES if "tcp" in family.protocols for port in family.ports
)
_MANUAL_UDP_PORTS = frozenset(
    port
    for family in _FAMILIES
    if family.protocols == frozenset({"udp"})
    for port in family.ports
)


@dataclass
class NseJob:
    """One Nmap invocation: a protocol, a port list, and a script list."""

    protocol: str
    ports: list[int]
    scripts: list[str]
    addresses: list[str] = field(default_factory=list)
    target_args: list[str] = field(default_factory=list)


@dataclass
class NseScope:
    """What this NSE run will scan and which scripts it selected."""

    mode: str
    target: str
    label: str
    input_path: Path | None
    jobs: list[NseJob]
    hosts: list[dict[str, Any]]
    skipped: list[dict[str, Any]]
    vuln: bool
    vuln_scripts: list[str]
    custom_scripts: list[str]


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``nse`` subcommand on the root CLI parser."""
    parser = subparsers.add_parser(
        "nse",
        help="Run the CPTS NSE scripts that match discovered services",
        description=(
            "CPTS phase 3: choose NSE scripts from the open ports and service "
            "names in an enum or discovery report, then run only those scripts. "
            "Use only against lab ranges or networks you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py nse --latest\n"
            "  python main.py nse --input reports/enum_10.10.10.10_20261118T224500.json\n"
            "  python main.py nse -t 10.10.10.10 -p 22,80,445\n"
            "  python main.py nse --latest --vuln\n"
            "  python main.py nse -t 10.10.10.10 -p 80 --custom-scripts http-title,banner\n"
        ),
    )
    parser.add_argument(
        "--input",
        help="Enum or discovery JSON to read hosts and open ports from",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use the newest reports/enum_*.json or reports/discovery_*.json",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Manual target: IPv4/IPv6, CIDR, hostname, or a file with one target per line",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Ports for manual mode. A wide range is reduced to the CPTS service ports",
    )
    parser.add_argument(
        "--vuln",
        action="store_true",
        help="Also run the vuln category, plus vulners when that script is installed",
    )
    parser.add_argument(
        "--custom-scripts",
        help="Extra NSE script names, comma-separated (for example banner,http-title)",
    )
    parser.set_defaults(func=_from_args)


def run_nse(
    *,
    target: str | None = None,
    ports: str | None = None,
    input_path: str | None = None,
    latest: bool = False,
    vuln: bool = False,
    custom_scripts: str | None = None,
) -> dict[str, Any]:
    """Select CPTS NSE scripts and run them against the matching ports.

    Args:
        target: Address, CIDR, hostname, or target-list path. Manual mode.
        ports: Port list used only with ``target``.
        input_path: Path to an enum or discovery JSON report.
        latest: Select the newest enum or discovery report under ``reports/``.
        vuln: Add the ``vuln`` category and ``vulners`` when it is installed.
        custom_scripts: Comma-separated NSE names to add to the selection.

    Returns:
        The structured report written under ``reports/``.

    Raises:
        NseError: The inputs disagree, no report exists, or a script name is unsafe.
        TargetError: A manual target is not an address, CIDR, hostname, or list.
        EnumError: The manual port list is not a valid Nmap port spec.
    """
    scope = resolve_scope(
        target=target,
        ports=ports,
        input_path=input_path,
        latest=latest,
        vuln=vuln,
        custom_scripts=custom_scripts,
    )
    runnable, skipped_udp = _drop_unprivileged_udp(scope.jobs)
    scope.skipped.extend(skipped_udp)
    scope.jobs = runnable

    reports_dir = ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    prefix = f"nse_{scope.label}_{stamp}"
    _print_plan(scope)

    results: list[NmapRunResult] = []
    if scope.jobs:
        console.print(f"[bold]NSE enumeration[/bold] ({scope.target})")
        results = _run_jobs(scope.jobs, reports_dir, prefix)
    else:
        console.print("[yellow]No NSE scripts were selected for this scope.[/yellow]")

    hosts = _merge_results(scope.hosts, _parse_results(results))
    report = _build_report(scope, hosts, results, reports_dir, prefix)
    json_path, markdown_path = _write_reports(report, reports_dir, prefix)
    _print_findings(hosts)
    console.print(f"\nJSON report: [cyan]{json_path}[/cyan]")
    console.print(f"Markdown summary: [cyan]{markdown_path}[/cyan]")
    for result in results:
        console.print(f"Nmap XML: [cyan]{result.xml_path}[/cyan]")
    return report


def resolve_scope(
    *,
    target: str | None,
    ports: str | None,
    input_path: str | None,
    latest: bool,
    vuln: bool,
    custom_scripts: str | None,
) -> NseScope:
    """Validate inputs and build the Nmap jobs for this run.

    ``--input``, ``--latest``, and ``-t`` are mutually exclusive. Manual mode
    requires ``-p``. A wide manual range is reduced to the known CPTS ports
    unless ``--custom-scripts`` asks for an explicit list.
    """
    chosen = [bool(input_path), bool(latest), bool(target)]
    if sum(chosen) != 1:
        raise NseError(
            "Choose one source: --input <report.json>, --latest, or -t with -p."
        )
    if ports and not target:
        raise NseError("-p is only valid with -t. A JSON report already lists the ports.")
    if target and not ports:
        raise NseError("Manual mode needs -p, for example -p 22,80,445.")

    extras = parse_custom_scripts(custom_scripts)
    vuln_scripts = vuln_script_names(vulners_script_installed()) if vuln else []

    if target:
        observed = manual_endpoints(ports or "", custom=bool(extras))
        target_args, label = load_target_args(target)
        hosts = [
            {
                "ip": "",
                "mac": "",
                "hostnames": [],
                "status": "up",
                "ports": [
                    {
                        "port": port,
                        "protocol": protocol,
                        "state": "open",
                        "service": "",
                        "selected_scripts": _scripts_for(port, protocol, "", vuln_scripts, extras),
                    }
                    for port, protocol in observed
                ],
            }
        ]
        jobs = _jobs_for_hosts(hosts, target_args=target_args)
        skipped = _skipped_from_spec(ports or "", observed, bool(extras))
        return NseScope(
            mode="manual",
            target=target,
            label=label,
            input_path=None,
            jobs=jobs,
            hosts=[host for host in hosts if host["ports"]],
            skipped=skipped,
            vuln=vuln,
            vuln_scripts=vuln_scripts,
            custom_scripts=extras,
        )

    path = find_latest_report(project_root() / "reports") if latest else Path(input_path or "")
    if not latest and not path.is_file():
        raise NseError(f"Report JSON not found: {path}")
    report_target, loaded, module_name = load_service_hosts(path)
    hosts, skipped = _annotate_hosts(loaded, vuln_scripts, extras)
    return NseScope(
        mode=module_name,
        target=report_target,
        label=_safe_label(report_target),
        input_path=path,
        jobs=_jobs_for_hosts(hosts),
        hosts=hosts,
        skipped=skipped,
        vuln=vuln,
        vuln_scripts=vuln_scripts,
        custom_scripts=extras,
    )


def scripts_for_port(port: int, protocol: str, service: str = "") -> list[str]:
    """Return the CPTS scripts that apply to one observed port.

    A port matches when its number is in the family and the protocol agrees,
    or when the service name is one of the family's names. The same script is
    not returned twice.
    """
    proto = (protocol or "tcp").lower()
    selected: list[str] = []
    for family in _FAMILIES:
        if proto not in family.protocols:
            continue
        if port in family.ports or _service_matches(service, family.services):
            selected.extend(family.scripts)
    return _dedupe(selected)


def parse_custom_scripts(raw: str | None) -> list[str]:
    """Validate a comma-separated list of NSE script names.

    Tokens must be script names or categories. Paths, option flags, and shell
    metacharacters are rejected so the value cannot change the Nmap command.

    Raises:
        NseError: A token is empty or not a plain script name.
    """
    if raw is None:
        return []
    if not raw.strip():
        raise NseError("Pass at least one script name to --custom-scripts, or omit the flag.")
    if any(char in raw for char in "\n\r\x00;|&$<>`(){}\\"):
        raise NseError(
            "--custom-scripts accepts comma-separated NSE names such as banner,http-title."
        )
    names: list[str] = []
    for token in raw.split(","):
        name = token.strip()
        if (
            not name
            or name.startswith("-")
            or name.startswith(".")
            or ".." in name
            or "/" in name
            or not _SCRIPT_TOKEN.fullmatch(name)
        ):
            raise NseError(f"Refusing unsafe NSE script name '{token.strip()}'.")
        if name not in names:
            names.append(name)
    return names


def vuln_script_names(vulners_available: bool) -> list[str]:
    """Return the vulnerability scripts to add when ``--vuln`` is set."""
    if vulners_available:
        return ["vuln", "vulners"]
    return ["vuln"]


def vulners_script_installed() -> bool:
    """Return whether the optional ``vulners`` NSE file is installed locally.

    This only looks at the Nmap script directory. It does not contact a target.
    """
    try:
        binary = Path(nmap_binary())
    except NmapNotFoundError:
        return False
    candidates = [
        binary.parent / "scripts" / "vulners.nse",
        binary.parent.parent / "share" / "nmap" / "scripts" / "vulners.nse",
        Path("/usr/share/nmap/scripts/vulners.nse"),
        Path("/usr/local/share/nmap/scripts/vulners.nse"),
    ]
    return any(path.is_file() for path in candidates)


def manual_endpoints(spec: str, *, custom: bool) -> list[tuple[int, str]]:
    """Turn a manual port spec into the ports that will actually be scanned.

    Without custom scripts, ranges are reduced to the CPTS service ports that
    fall inside them. Port 161 is scheduled as UDP. Every other selected port
    is TCP, including DNS/53. With custom scripts, the spec is used as given,
    but a range wider than 128 ports is rejected.
    """
    normalized = normalize_port_spec(spec)
    endpoints: list[tuple[int, str]] = []
    for token in normalized.split(","):
        start_text, separator, end_text = token.partition("-")
        start = int(start_text)
        end = int(end_text) if separator else start
        if custom and (end - start + 1) > _MAX_CUSTOM_PORTS:
            raise NseError(
                "Custom scripts need an explicit port list of at most "
                f"{_MAX_CUSTOM_PORTS} ports, not a wide range like {token}."
            )
        for port in range(start, end + 1):
            if not custom and not _manual_port_selected(port):
                continue
            protocol = "udp" if port in _MANUAL_UDP_PORTS and not custom else "tcp"
            endpoint = (port, protocol)
            if endpoint not in endpoints:
                endpoints.append(endpoint)
    if not endpoints:
        raise NseError(
            "None of those ports map to a CPTS NSE family. "
            "Pass a known service port or add --custom-scripts."
        )
    return endpoints


def find_latest_report(reports_dir: Path) -> Path:
    """Return the newest enum or discovery JSON in ``reports_dir``.

    Enum reports win when they are newer because they carry service names.
    NSE reports are ignored so ``--latest`` cannot select its own output.

    Raises:
        NseError: The directory is missing or has no enum or discovery report.
    """
    if not reports_dir.is_dir():
        raise NseError("No reports/ directory yet. Run enum or discovery first, or pass -t and -p.")
    candidates = [
        path
        for pattern in ("enum_*.json", "discovery_*.json")
        for path in reports_dir.glob(pattern)
        if path.is_file()
    ]
    if not candidates:
        raise NseError(
            f"No enum or discovery JSON in {reports_dir}. "
            "Run one of those modules first, or pass -t and -p."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def load_service_hosts(path: Path) -> tuple[str, list[dict[str, Any]], str]:
    """Read live hosts, protocols, and service names from an enum or discovery JSON.

    Addresses are checked with :mod:`ipaddress` so a report cannot inject
    extra Nmap arguments.

    Returns:
        The report target, the host dicts, and the ``module`` field (or
        ``report`` when the file does not name one).

    Raises:
        NseError: The file is missing, not JSON, or has no host list.
    """
    if not path.is_file():
        raise NseError(f"Report JSON not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise NseError(f"Could not read '{path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise NseError(f"Invalid JSON in '{path}': {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("hosts"), list):
        raise NseError(f"'{path}' has no hosts list.")

    module = str(payload.get("module") or "report")
    if module not in {"discovery", "enum", "report"}:
        console.print(
            "[yellow]Input JSON was not produced by enum or discovery. "
            "Open ports and service names will be used anyway.[/yellow]"
        )
    target = str(payload.get("target") or path.stem)
    hosts: list[dict[str, Any]] = []
    for index, entry in enumerate(payload["hosts"], start=1):
        if not isinstance(entry, dict):
            raise NseError(f"Host entry {index} in '{path}' is not an object.")
        if str(entry.get("status") or "up") != "up":
            continue
        ip_raw = str(entry.get("ip") or "").strip()
        if not ip_raw:
            continue
        try:
            ip = str(ipaddress.ip_address(ip_raw))
        except ValueError as exc:
            raise NseError(
                f"Host entry {index} in '{path}' has an invalid address '{ip_raw}'."
            ) from exc
        hosts.append(
            {
                "ip": ip,
                "mac": str(entry.get("mac") or ""),
                "hostnames": [
                    str(name)
                    for name in (entry.get("hostnames") or [])
                    if isinstance(name, str) and name.strip()
                ],
                "status": "up",
                "ports": _ports_from_entry(entry, path, index),
            }
        )
    return target, hosts, module


def _from_args(args: argparse.Namespace) -> int:
    run_nse(
        target=args.target,
        ports=args.ports,
        input_path=args.input,
        latest=args.latest,
        vuln=args.vuln,
        custom_scripts=args.custom_scripts,
    )
    return 0


def _scripts_for(
    port: int,
    protocol: str,
    service: str,
    vuln_scripts: list[str],
    custom_scripts: list[str],
) -> list[str]:
    """Return scripts for one port.

    Vulnerability scripts are added only to ports that already match a CPTS
    family, or to ports the operator explicitly included with custom scripts.
    ``--vuln`` alone does not sweep every open port.
    """
    base = scripts_for_port(port, protocol, service)
    if base:
        return _dedupe([*base, *vuln_scripts, *custom_scripts])
    if custom_scripts:
        return _dedupe([*custom_scripts, *vuln_scripts])
    return []


def _annotate_hosts(
    hosts: list[dict[str, Any]],
    vuln_scripts: list[str],
    custom_scripts: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for host in hosts:
        selected_ports: list[dict[str, Any]] = []
        for port in host["ports"]:
            scripts = _scripts_for(
                int(port["port"]),
                str(port["protocol"]),
                str(port.get("service") or ""),
                vuln_scripts,
                custom_scripts,
            )
            if not scripts:
                skipped.append(
                    {
                        "ip": host["ip"],
                        "port": port["port"],
                        "protocol": port["protocol"],
                        "service": port.get("service") or "",
                        "reason": "no CPTS script mapping",
                    }
                )
                continue
            selected_ports.append({**port, "selected_scripts": scripts})
        if selected_ports:
            kept.append({**host, "ports": selected_ports})
    return kept, skipped


def _jobs_for_hosts(hosts: list[dict[str, Any]], target_args: list[str] | None = None) -> list[NseJob]:
    grouped: dict[tuple[str, tuple[int, ...], tuple[str, ...]], list[str]] = {}
    order: list[tuple[str, tuple[int, ...], tuple[str, ...]]] = []
    for host in hosts:
        by_proto_ports: dict[str, list[int]] = {}
        by_proto_scripts: dict[str, list[str]] = {}
        for port in host.get("ports") or []:
            scripts = list(port.get("selected_scripts") or [])
            if not scripts:
                continue
            proto = str(port["protocol"])
            number = int(port["port"])
            ports = by_proto_ports.setdefault(proto, [])
            if number not in ports:
                ports.append(number)
            known = by_proto_scripts.setdefault(proto, [])
            for script in scripts:
                if script not in known:
                    known.append(script)
        for proto, ports in by_proto_ports.items():
            key = (proto, tuple(sorted(ports)), tuple(by_proto_scripts[proto]))
            if key not in grouped:
                grouped[key] = []
                order.append(key)
            ip = str(host.get("ip") or "")
            if ip and ip not in grouped[key]:
                grouped[key].append(ip)
    jobs: list[NseJob] = []
    for proto, ports, scripts in order:
        jobs.append(
            NseJob(
                protocol=proto,
                ports=list(ports),
                scripts=list(scripts),
                addresses=grouped[(proto, ports, scripts)],
                target_args=list(target_args or []),
            )
        )
    return jobs


def _drop_unprivileged_udp(jobs: list[NseJob]) -> tuple[list[NseJob], list[dict[str, Any]]]:
    udp = [job for job in jobs if job.protocol == "udp"]
    tcp = [job for job in jobs if job.protocol != "udp"]
    if not udp or has_admin_privileges():
        return jobs, []
    console.print(
        "[yellow]UDP NSE scripts (SNMP, and DNS on UDP) need raw sockets. "
        f"Those probes were skipped. {privilege_hint()}[/yellow]"
    )
    skipped: list[dict[str, Any]] = []
    for job in udp:
        targets = job.addresses or ["manual"]
        for ip in targets:
            for port in job.ports:
                skipped.append(
                    {
                        "ip": ip,
                        "port": port,
                        "protocol": "udp",
                        "service": "",
                        "reason": "UDP NSE needs administrator or root privileges",
                    }
                )
    return tcp, skipped


def _run_jobs(jobs: list[NseJob], reports_dir: Path, prefix: str) -> list[NmapRunResult]:
    results: list[NmapRunResult] = []
    width = len(str(len(jobs)))
    for index, job in enumerate(jobs, start=1):
        suffix = f"_{job.protocol}.xml" if len(jobs) == 1 else f"_{job.protocol}_{index:0{width}d}.xml"
        xml_path = reports_dir / f"{prefix}{suffix}"
        if job.addresses:
            targets = _targets_to_args(job.addresses, reports_dir, f"{prefix}_{index}")
        else:
            targets = job.target_args
        arguments = [*_scan_arguments(job), *targets]
        console.print(_format_command_preview(["nmap", *arguments]))
        results.append(run_nmap(arguments, xml_path))
    return results


def _scan_arguments(job: NseJob) -> list[str]:
    port_spec = ",".join(str(port) for port in job.ports)
    script_spec = ",".join(job.scripts)
    arguments = ["-n", "-Pn", "-sV", "-p", port_spec, "--script", script_spec]
    if job.protocol == "udp":
        arguments.insert(0, "-sU")
    return arguments


def _targets_to_args(ips: list[str], reports_dir: Path, prefix: str) -> list[str]:
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


def _merge_results(
    planned: list[dict[str, Any]],
    scanned: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach NSE output to the ports that were selected.

    Hostnames from the input report are kept because the scan runs with ``-n``.
    Manual mode has no addresses until Nmap returns them, so those results
    become the host list and inherit the planned script selection.
    """
    scanned_by_ip = {str(host.get("ip") or ""): host for host in scanned if host.get("ip")}
    planned_with_ip = [host for host in planned if host.get("ip")]
    if not planned_with_ip:
        template = planned[0]["ports"] if planned else []
        merged = [_host_from_scan(host, template) for host in scanned if host.get("ip")]
        _sort_hosts(merged)
        return merged

    merged = []
    seen: set[str] = set()
    for planned_host in planned_with_ip:
        ip = str(planned_host["ip"])
        seen.add(ip)
        merged.append(_overlay_host(planned_host, scanned_by_ip.get(ip)))
    for ip, scanned_host in scanned_by_ip.items():
        if ip not in seen:
            merged.append(_host_from_scan(scanned_host, []))
    _sort_hosts(merged)
    return merged


def _overlay_host(planned_host: dict[str, Any], scanned_host: dict[str, Any] | None) -> dict[str, Any]:
    scanned_ports = {
        (port.get("port"), port.get("protocol")): port
        for port in (scanned_host or {}).get("ports") or []
    }
    ports: list[dict[str, Any]] = []
    for planned_port in planned_host.get("ports") or []:
        found = scanned_ports.get((planned_port.get("port"), planned_port.get("protocol")), {})
        ports.append(
            {
                "port": planned_port.get("port"),
                "protocol": planned_port.get("protocol"),
                "state": found.get("state") or planned_port.get("state") or "open",
                "service": found.get("service") or planned_port.get("service") or "",
                "selected_scripts": list(planned_port.get("selected_scripts") or []),
                "scripts": list(found.get("scripts") or []),
            }
        )
    return {
        "ip": planned_host.get("ip") or (scanned_host or {}).get("ip") or "",
        "mac": str((scanned_host or {}).get("mac") or planned_host.get("mac") or ""),
        "hostnames": list((scanned_host or {}).get("hostnames") or planned_host.get("hostnames") or []),
        "status": str((scanned_host or {}).get("status") or planned_host.get("status") or "up"),
        "scripts": list((scanned_host or {}).get("scripts") or []),
        "ports": ports,
    }


def _host_from_scan(scanned_host: dict[str, Any], template: list[dict[str, Any]]) -> dict[str, Any]:
    template_by_key = {
        (port.get("port"), port.get("protocol")): list(port.get("selected_scripts") or [])
        for port in template
    }
    ports = []
    for port in scanned_host.get("ports") or []:
        if port.get("state") not in _INTERESTING_STATES:
            continue
        key = (port.get("port"), port.get("protocol"))
        ports.append(
            {
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "state": port.get("state"),
                "service": port.get("service") or "",
                "selected_scripts": template_by_key.get(key, []),
                "scripts": list(port.get("scripts") or []),
            }
        )
    return {
        "ip": scanned_host.get("ip") or "",
        "mac": scanned_host.get("mac") or "",
        "hostnames": list(scanned_host.get("hostnames") or []),
        "status": scanned_host.get("status") or "up",
        "scripts": list(scanned_host.get("scripts") or []),
        "ports": ports,
    }


def _ports_from_entry(entry: dict[str, Any], path: Path, index: int) -> list[dict[str, Any]]:
    raw_ports = entry.get("ports") or []
    if not isinstance(raw_ports, list):
        raise NseError(f"Host entry {index} in '{path}' has an invalid ports list.")
    ports: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for port in raw_ports:
        if not isinstance(port, dict):
            raise NseError(f"Host entry {index} in '{path}' has an invalid port object.")
        state = str(port.get("state") or "open")
        if state not in _INTERESTING_STATES:
            continue
        number = port.get("port")
        if isinstance(number, str) and number.isdigit():
            number = int(number)
        if not isinstance(number, int) or not 1 <= number <= 65535:
            raise NseError(
                f"Host entry {index} in '{path}' has an invalid port: {port.get('port')}"
            )
        protocol = str(port.get("protocol") or "tcp").lower()
        if protocol not in {"tcp", "udp"}:
            raise NseError(
                f"Host entry {index} in '{path}' has an invalid protocol '{protocol}'."
            )
        key = (number, protocol)
        if key in seen:
            continue
        seen.add(key)
        ports.append(
            {
                "port": number,
                "protocol": protocol,
                "state": state,
                "service": str(port.get("service") or ""),
            }
        )
    return ports


def _skipped_from_spec(
    spec: str,
    observed: list[tuple[int, str]],
    custom: bool,
) -> list[dict[str, Any]]:
    if custom:
        return []
    normalized = normalize_port_spec(spec)
    requested: set[int] = set()
    for token in normalized.split(","):
        start_text, separator, end_text = token.partition("-")
        start = int(start_text)
        end = int(end_text) if separator else start
        if end - start > 32:
            return [
                {
                    "ip": "manual",
                    "port": token,
                    "protocol": "",
                    "service": "",
                    "reason": "range reduced to CPTS service ports",
                }
            ]
        requested.update(range(start, end + 1))
    chosen = {port for port, _protocol in observed}
    return [
        {
            "ip": "manual",
            "port": port,
            "protocol": "tcp",
            "service": "",
            "reason": "no CPTS script mapping",
        }
        for port in sorted(requested - chosen)
    ]


def _manual_port_selected(port: int) -> bool:
    return port in _MANUAL_TCP_PORTS or port in _MANUAL_UDP_PORTS


def _service_matches(service: str, names: frozenset[str]) -> bool:
    cleaned = service.lower().strip()
    if not cleaned:
        return False
    if cleaned in names:
        return True
    tail = cleaned.split("/")[-1]
    return tail in names and tail != cleaned


def _print_plan(scope: NseScope) -> None:
    if scope.vuln:
        available = ", ".join(scope.vuln_scripts)
        console.print(f"[bold]Vulnerability scripts[/bold]: {available}")
    if scope.custom_scripts:
        console.print("[bold]Custom scripts[/bold]: " + ", ".join(scope.custom_scripts))
    for job in scope.jobs:
        ports = ",".join(str(port) for port in job.ports)
        targets = ", ".join(job.addresses) if job.addresses else scope.target
        console.print(
            f"[bold]{job.protocol.upper()}[/bold] {targets} ports {ports}\n"
            f"  scripts: {', '.join(job.scripts)}"
        )
    if scope.skipped:
        console.print(f"[yellow]Skipped {len(scope.skipped)} port(s) with no script selection.[/yellow]")


def _print_findings(hosts: list[dict[str, Any]]) -> None:
    findings = 0
    for host in hosts:
        names = ", ".join(host.get("hostnames") or [])
        title = str(host.get("ip") or "unknown")
        if names:
            title = f"{title} ({names})"
        console.print(f"\n[bold cyan]{escape(title)}[/bold cyan]")
        host_scripts = list(host.get("scripts") or [])
        if host_scripts:
            console.print("  [bold]host[/bold]")
            findings += _print_script_block("    ", host_scripts)
        for port in host.get("ports") or []:
            label = f"{port.get('port')}/{port.get('protocol')} {port.get('service') or ''}".strip()
            console.print(f"  [bold]{escape(label)}[/bold]")
            findings += _print_script_block("    ", port.get("scripts") or [])
            if not port.get("scripts"):
                console.print("    [dim](no script output)[/dim]")
    console.print(f"\nHosts: {len(hosts)} | Script results: {findings}")


def _print_script_block(indent: str, scripts: list[dict[str, Any]]) -> int:
    shown = 0
    for script in scripts:
        script_id = str(script.get("id") or "script")
        output = str(script.get("output") or "").strip() or "(no output)"
        lines = output.splitlines() or ["(no output)"]
        console.print(f"{indent}[green]{escape(script_id)}[/green]")
        visible = lines[:_CONSOLE_LINES]
        for line in visible:
            console.print(f"{indent}  {escape(line)}")
        if len(lines) > _CONSOLE_LINES:
            extra = len(lines) - _CONSOLE_LINES
            console.print(f"{indent}  [dim]... {extra} more lines in the JSON report[/dim]")
        shown += 1
    return shown


def _build_report(
    scope: NseScope,
    hosts: list[dict[str, Any]],
    results: list[NmapRunResult],
    reports_dir: Path,
    prefix: str,
) -> dict[str, Any]:
    return {
        "module": "nse",
        "source": scope.mode,
        "input": _relative(scope.input_path) if scope.input_path else None,
        "target": scope.target,
        "vuln": scope.vuln,
        "vuln_scripts": scope.vuln_scripts,
        "custom_scripts": scope.custom_scripts,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hosts": hosts,
        "skipped": scope.skipped,
        "artifacts": {
            "json": _relative(reports_dir / f"{prefix}.json"),
            "markdown": _relative(reports_dir / f"{prefix}.md"),
            "xml": [_relative(result.xml_path) for result in results],
        },
        "commands": [result.command for result in results],
    }


def _write_reports(report: dict[str, Any], reports_dir: Path, prefix: str) -> tuple[Path, Path]:
    json_path = reports_dir / f"{prefix}.json"
    markdown_path = reports_dir / f"{prefix}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def _render_markdown(report: dict[str, Any]) -> str:
    source = report.get("input") or "manual"
    lines = [
        "# NSE enumeration",
        "",
        f"- Target: `{report['target']}`",
        f"- Source: `{source}`",
        f"- Vulnerability scripts: {', '.join(report['vuln_scripts']) or 'no'}",
        f"- Custom scripts: {', '.join(report['custom_scripts']) or 'no'}",
        f"- Generated: {report['generated_at']}",
        "",
    ]
    hosts: list[dict[str, Any]] = report["hosts"]
    if not hosts:
        lines.extend(["No NSE results were recorded.", ""])
    for host in hosts:
        names = ", ".join(host.get("hostnames") or [])
        lines.append(f"## {host.get('ip') or 'unknown'}" + (f" ({names})" if names else ""))
        lines.append("")
        if host.get("scripts"):
            lines.append("Host scripts:")
            lines.append("")
            for script in host["scripts"]:
                lines.extend(_markdown_script(script))
        for port in host.get("ports") or []:
            service = port.get("service") or "unknown"
            lines.append(f"### {port.get('port')}/{port.get('protocol')} {service}")
            lines.append("")
            selected = ", ".join(port.get("selected_scripts") or []) or "-"
            lines.append(f"Selected: `{selected}`")
            lines.append("")
            if not port.get("scripts"):
                lines.append("No script output.")
                lines.append("")
                continue
            for script in port["scripts"]:
                lines.extend(_markdown_script(script))
    skipped: list[dict[str, Any]] = report.get("skipped") or []
    if skipped:
        lines.extend(["## Skipped", ""])
        for item in skipped:
            lines.append(
                f"- {item.get('ip')} {item.get('port')}/{item.get('protocol') or '-'} "
                f"({item.get('service') or '-'}): {item.get('reason')}"
            )
        lines.append("")
    return "\n".join(lines)


def _markdown_script(script: dict[str, Any]) -> list[str]:
    output = str(script.get("output") or "").strip() or "(no output)"
    output = output.replace("```", "'''")
    return [
        f"`{script.get('id') or 'script'}`",
        "",
        "```text",
        output,
        "```",
        "",
    ]


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


def _dedupe(items: list[str]) -> list[str]:
    unique: list[str] = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return unique


def _sort_hosts(hosts: list[dict[str, Any]]) -> None:
    def sort_key(host: dict[str, Any]) -> tuple[int, Any]:
        ip = str(host.get("ip") or "")
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    hosts.sort(key=sort_key)
