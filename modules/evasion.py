#!/usr/bin/env python3
"""Firewall mapping and selectable IDS/IPS evasion for authorized lab scans.

CPTS phase 4. ``firewall-map`` sends a TCP ACK probe (``-sA -Pn -n``) so a
stateful filter shows up as ``filtered`` and a port that answers with RST
shows up as ``unfiltered``. ACK mode does not separate open from closed.
``stealth-evasion`` sends a SYN probe (``-sS``) and adds only the options
you select: a source port, IP fragmentation, random decoys, and a slow
timing template. Every profile needs raw sockets, so the module stops
before Nmap when the process is not elevated.
"""

from __future__ import annotations

import os
import sys

_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [
    entry
    for entry in sys.path
    if os.path.normcase(os.path.abspath(entry or os.getcwd())) != os.path.normcase(_script_dir)
]

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
import ipaddress
import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from core.parser import parse_nmap_xml
from core.runner import (
    NmapError,
    NmapPrivilegeError,
    NmapRunResult,
    ensure_reports_dir,
    has_admin_privileges,
    privilege_hint,
    project_root,
    run_nmap,
)
from modules.discovery import TargetError, load_target_args
from modules.enum import (
    EnumError,
    find_latest_discovery,
    load_discovery_hosts,
    normalize_port_spec,
)

console = Console()

MODES = ("firewall-map", "stealth-evasion")
# Common CPTS service ports. Used only when -p is omitted, and printed in the
# Nmap command so the default is visible in the study notes.
DEFAULT_PORTS = "21,22,53,80,88,135,139,443,445,3389,8080"
DEFAULT_SOURCE_PORT = 53
MAX_DECOYS = 25
_MAX_DELAY_MS = 30 * 60 * 1000
_SCAN_DELAY = re.compile(r"^([0-9]+)(ms|s|m|h)?$")
_DELAY_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}
_STATE_ORDER = ("open", "closed", "filtered", "unfiltered", "open|filtered")
_STATE_STYLE = {
    "open": "green",
    "closed": "dim",
    "filtered": "yellow",
    "unfiltered": "cyan",
    "open|filtered": "yellow",
}
_STEALTH_FLAGS = ("--source-port", "--fragment", "--mtu", "--decoys", "--timing", "--scan-delay")


class EvasionError(ValueError):
    """The evasion mode, ports, or technique combination is not usable."""


@dataclass
class EvasionProfile:
    """Technique flags for one evasion run, after defaults are applied."""

    mode: str
    source_port: int | None = None
    fragment: bool = False
    mtu: int | None = None
    decoys: int | None = None
    timing: int | None = None
    scan_delay: str | None = None

    def summary(self) -> str:
        """Return a short label of the options that will be sent to Nmap."""
        if self.mode == "firewall-map":
            return "TCP ACK (-sA -Pn -n)"
        parts = [f"TCP SYN (-sS), source port {self.source_port}"]
        if self.fragment:
            parts.append("fragment (-f)")
        if self.mtu is not None:
            parts.append(f"mtu {self.mtu}")
        if self.decoys is not None:
            parts.append(f"decoys RND:{self.decoys}")
        if self.timing is not None:
            parts.append(f"T{self.timing}")
        if self.scan_delay:
            parts.append(f"delay {self.scan_delay}")
        return ", ".join(parts)


@dataclass
class EvasionJob:
    """One Nmap invocation, before a long host list is written to ``-iL``."""

    port_spec: str
    addresses: list[str] = field(default_factory=list)
    target_args: list[str] = field(default_factory=list)


@dataclass
class EvasionScope:
    """Targets and technique profile selected for one run."""

    mode: str
    target: str
    label: str
    input_path: Path | None
    jobs: list[EvasionJob]
    profile: EvasionProfile
    used_default_ports: bool


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the ``evasion`` subcommand on the root CLI parser."""
    parser = subparsers.add_parser(
        "evasion",
        help="Map a stateful firewall or apply selectable IDS/IPS evasion options",
        description=(
            "CPTS phase 4: TCP ACK firewall map (-sA -Pn -n) or a SYN scan "
            "with a source port, fragmentation, decoys, and slow timing. "
            "Use only against lab ranges or networks you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py evasion 10.10.10.10\n"
            "  python main.py evasion -t 10.10.10.10 -p 22,80,443\n"
            "  python main.py evasion --mode stealth-evasion 10.10.10.10 -p 80 "
            "--source-port 53 --fragment --decoys 5 --timing 2 --scan-delay 500ms\n"
            "  python modules/evasion.py 10.10.10.10 -p 22,80,443\n"
        ),
    )
    _add_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    """Build the parser used when this file is executed directly."""
    parser = argparse.ArgumentParser(
        prog="evasion",
        description=(
            "CPTS phase 4: map a stateful firewall with a TCP ACK scan, or "
            "send a SYN scan with selectable evasion options. "
            "Pass the target as the first argument or with -t. "
            "Use only against lab ranges or networks you are authorized to test."
        ),
        epilog=(
            "examples:\n"
            "  python modules/evasion.py 10.10.10.10\n"
            "  python3 modules/evasion.py 10.10.10.10 -p 22,80,443\n"
            "  python modules/evasion.py --mode stealth-evasion -t 10.10.10.10 -p 80 "
            "--mtu 24 --source-port 88 --timing 2 --scan-delay 500ms\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_arguments(parser)
    return parser


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the evasion arguments shared by ``main.py`` and direct execution."""
    parser.add_argument(
        "target_arg",
        nargs="?",
        metavar="target",
        help="IPv4/IPv6 address, CIDR range, hostname, or a file with one target per line",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        help="Same as the positional target. Use one of the two, not two different values",
    )
    parser.add_argument(
        "--input",
        help="Discovery JSON to read live hosts and open TCP ports from",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Use the newest reports/discovery_*.json",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help=(
            "TCP ports, for example 22,80,443 or 1-1024. "
            f"Omit to use {DEFAULT_PORTS}. Pass - to scan every TCP port (-p-)"
        ),
    )
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="firewall-map",
        help=(
            "firewall-map: TCP ACK scan (-sA -Pn -n). "
            "stealth-evasion: SYN scan plus the technique flags below "
            "(default: firewall-map)"
        ),
    )
    parser.add_argument(
        "--source-port",
        type=int,
        help=(
            "Source port for stealth-evasion (--source-port). "
            f"Defaults to {DEFAULT_SOURCE_PORT} (DNS). Use 88 to resemble Kerberos"
        ),
    )
    parser.add_argument(
        "--fragment",
        action="store_true",
        help="Fragment packets (-f). Cannot be combined with --mtu",
    )
    parser.add_argument(
        "--mtu",
        type=int,
        help="Fragment using this MTU (--mtu). Must be a multiple of 8, such as 16 or 24",
    )
    parser.add_argument(
        "--decoys",
        type=int,
        metavar="N",
        help=f"Hide the real address among N random decoys (-D RND:N, 1-{MAX_DECOYS})",
    )
    parser.add_argument(
        "--timing",
        type=int,
        choices=(0, 1, 2),
        help="Slow timing template (-T0, -T1, or -T2) for IDS/IPS thresholds",
    )
    parser.add_argument(
        "--scan-delay",
        dest="scan_delay",
        help="Pause between probes, for example 500ms (-T2 --scan-delay 500ms). Max 30 minutes",
    )
    parser.set_defaults(func=_from_args)


def run_evasion(
    *,
    target: str | None = None,
    ports: str | None = None,
    input_path: str | None = None,
    latest: bool = False,
    mode: str = "firewall-map",
    source_port: int | None = None,
    fragment: bool = False,
    mtu: int | None = None,
    decoys: int | None = None,
    timing: int | None = None,
    scan_delay: str | None = None,
) -> dict[str, Any]:
    """Map firewall state or run a SYN scan with the selected evasion options.

    Args:
        target: Address, CIDR, hostname, or target-list path.
        ports: TCP port spec. Omit it to use the CPTS service-port set.
        input_path: Discovery JSON whose live hosts supply the targets.
        latest: Select the newest ``reports/discovery_*.json``.
        mode: ``firewall-map`` or ``stealth-evasion``.
        source_port: SYN source port. Defaults to 53 in stealth mode.
        fragment: Add ``-f``. Mutually exclusive with ``mtu``.
        mtu: Add ``--mtu``. Must be a positive multiple of 8.
        decoys: Number of random ``-D RND:`` decoys.
        timing: Nmap timing template 0, 1, or 2.
        scan_delay: Inter-probe delay such as ``500ms``.

    Returns:
        The structured report written under ``reports/``.

    Raises:
        EvasionError: The mode and the technique flags disagree, or a value
            is outside the accepted range.
        TargetError: The manual target is not an address, CIDR, hostname, or list.
        EnumError: The port list or the discovery JSON is not usable.
        NmapPrivilegeError: The process cannot open raw sockets.
    """
    scope = resolve_scope(
        target=target,
        ports=ports,
        input_path=input_path,
        latest=latest,
        mode=mode,
        source_port=source_port,
        fragment=fragment,
        mtu=mtu,
        decoys=decoys,
        timing=timing,
        scan_delay=scan_delay,
    )
    if scope.used_default_ports:
        console.print(
            f"[bold]Ports[/bold] default to the CPTS service set ({scope.jobs[0].port_spec})."
        )
    console.print(f"[bold]{scope.mode}[/bold] — {scope.profile.summary()}")
    if scope.mode == "firewall-map":
        console.print(
            "ACK results: [yellow]filtered[/yellow] was dropped by a stateful filter; "
            "[cyan]unfiltered[/cyan] returned RST, so the port is not filtered. "
            "This probe does not tell open from closed."
        )
    for job in scope.jobs:
        preview_targets = job.target_args or job.addresses
        preview = build_scan_arguments(scope.profile, job.port_spec, preview_targets)
        console.print(f"[bold]Nmap command[/bold]\n{shlex.join(['nmap', *preview])}")

    _require_privileges(scope.mode)
    reports_dir = ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    prefix = f"evasion_{scope.label}_{stamp}"
    results = _run_jobs(scope, reports_dir, prefix)
    hosts = _hosts_from_results(results)
    report = _build_report(scope, hosts, results, reports_dir, prefix)
    json_path, markdown_path = _write_reports(report, reports_dir, prefix)
    _print_results_table(hosts, report["state_counts"])
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
    mode: str,
    source_port: int | None,
    fragment: bool,
    mtu: int | None,
    decoys: int | None,
    timing: int | None,
    scan_delay: str | None,
) -> EvasionScope:
    """Validate the CLI and describe the Nmap jobs for this run.

    A target, ``--input``, and ``--latest`` are mutually exclusive. Stealth
    flags are rejected in firewall-map mode. ``-p`` overrides the open ports
    stored in a discovery report.
    """
    if mode not in MODES:
        allowed = ", ".join(MODES)
        raise EvasionError(f"Unknown mode '{mode}'. Choose one of: {allowed}.")
    chosen = [bool(input_path), bool(latest), bool(target)]
    if sum(chosen) != 1:
        raise EvasionError(
            "Choose one source: a target (positional or -t), --input <discovery.json>, or --latest."
        )
    profile = resolve_profile(
        mode=mode,
        source_port=source_port,
        fragment=fragment,
        mtu=mtu,
        decoys=decoys,
        timing=timing,
        scan_delay=scan_delay,
    )
    port_spec, used_default = resolve_port_spec(ports)

    if target:
        target_args, label = load_target_args(target)
        return EvasionScope(
            mode=mode,
            target=target,
            label=label,
            input_path=None,
            jobs=[EvasionJob(port_spec=port_spec, target_args=target_args)],
            profile=profile,
            used_default_ports=used_default,
        )

    path = find_latest_discovery(project_root() / "reports") if latest else Path(input_path or "")
    if not latest and not path.is_file():
        raise EvasionError(f"Discovery JSON not found: {path}")
    discovered_target, hosts = load_discovery_hosts(path)
    jobs = _jobs_from_discovery(hosts, port_spec, override_ports=ports is not None)
    if not jobs:
        if not any(host.get("ip") for host in hosts):
            raise EvasionError(
                f"'{path}' has no live hosts to scan. Run discovery again or pass a target."
            )
        raise EvasionError(
            f"'{path}' has no open TCP ports. Pass -p to choose which ports to probe."
        )
    return EvasionScope(
        mode=mode,
        target=discovered_target,
        label=_safe_label(discovered_target),
        input_path=path,
        jobs=jobs,
        profile=profile,
        used_default_ports=False,
    )


def resolve_profile(
    *,
    mode: str,
    source_port: int | None,
    fragment: bool,
    mtu: int | None,
    decoys: int | None,
    timing: int | None,
    scan_delay: str | None,
) -> EvasionProfile:
    """Check technique flags and apply the stealth-mode source-port default.

    ``--fragment`` and ``--mtu`` cannot be combined: Nmap rejects that pair.
    Firewall-map mode accepts none of the stealth flags.

    Raises:
        EvasionError: A flag is used in the wrong mode or has an invalid value.
    """
    stealth_requested = any(
        (
            source_port is not None,
            fragment,
            mtu is not None,
            decoys is not None,
            timing is not None,
            bool(scan_delay),
        )
    )
    if mode == "firewall-map":
        if stealth_requested:
            flags = ", ".join(_STEALTH_FLAGS)
            raise EvasionError(
                f"Stealth flags ({flags}) apply only to --mode stealth-evasion. "
                "firewall-map sends -sA -Pn -n and optional -p."
            )
        return EvasionProfile(mode=mode)

    resolved_source = DEFAULT_SOURCE_PORT if source_port is None else source_port
    if not 1 <= resolved_source <= 65535:
        raise EvasionError("--source-port must be a TCP port from 1 to 65535.")
    if fragment and mtu is not None:
        raise EvasionError(
            "--fragment (-f) and --mtu cannot be combined. Choose one fragmentation style."
        )
    if mtu is not None:
        validate_mtu(mtu)
    if decoys is not None and not 1 <= decoys <= MAX_DECOYS:
        raise EvasionError(f"--decoys must be an integer from 1 to {MAX_DECOYS}.")
    if timing is not None and timing not in (0, 1, 2):
        raise EvasionError("--timing must be 0, 1, or 2 (-T0, -T1, -T2).")
    delay = validate_scan_delay(scan_delay) if scan_delay else None
    return EvasionProfile(
        mode=mode,
        source_port=resolved_source,
        fragment=fragment,
        mtu=mtu,
        decoys=decoys,
        timing=timing,
        scan_delay=delay,
    )


def resolve_port_spec(ports: str | None) -> tuple[str, bool]:
    """Return the Nmap port spec and whether the built-in default was used.

    A lone ``-`` becomes Nmap's all-ports form (``-p-``). Any other value is
    checked by the same port parser the enum module uses.

    Raises:
        EnumError: The list contains a port outside 1-65535 or an unsafe token.
    """
    if ports is None or not ports.strip():
        return DEFAULT_PORTS, True
    if ports.strip() == "-":
        return "-", False
    return normalize_port_spec(ports), False


def validate_mtu(mtu: int) -> None:
    """Reject an MTU that Nmap would not accept for ``--mtu``.

    The value has to be a positive multiple of 8. 16 and 24 are the sizes
    used when a lab IDS does not reassemble small fragments.

    Raises:
        EvasionError: ``mtu`` is not a usable multiple of 8.
    """
    if mtu <= 0 or mtu % 8 != 0 or mtu > 1500:
        raise EvasionError(
            "--mtu must be a multiple of 8 between 8 and 1500 (for example 16 or 24)."
        )


def validate_scan_delay(value: str) -> str:
    """Return a delay string Nmap can pass to ``--scan-delay``.

    A bare number is seconds, matching Nmap. ``ms``, ``s``, ``m``, and ``h``
    keep their usual meaning. The delay is capped at 30 minutes so a typo
    cannot stall the lab scan indefinitely.

    Raises:
        EvasionError: The value is empty, zero, or not a plain duration.
    """
    raw = value.strip()
    match = _SCAN_DELAY.fullmatch(raw)
    if match is None:
        raise EvasionError(
            "--scan-delay must be a duration such as 500ms, 1s, or 2s. "
            "A bare number is seconds."
        )
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    delay_ms = amount * _DELAY_MS[unit]
    if delay_ms <= 0:
        raise EvasionError("--scan-delay must be greater than zero.")
    if delay_ms > _MAX_DELAY_MS:
        raise EvasionError("--scan-delay cannot be longer than 30 minutes.")
    return raw


def build_scan_arguments(
    profile: EvasionProfile,
    port_spec: str,
    target_args: list[str],
) -> list[str]:
    """Return the Nmap arguments for one job, without the binary or ``-oX``.

    Firewall map is exactly ``-sA -Pn -n`` plus the port list. Stealth mode
    starts from ``-sS -Pn -n --source-port`` and appends only the options
    present on the profile. ``-D RND:<N>`` is passed as two argv items so a
    decoy count cannot be read as another flag.
    """
    if profile.mode == "firewall-map":
        arguments = ["-sA", "-Pn", "-n"]
    else:
        source_port = profile.source_port if profile.source_port is not None else DEFAULT_SOURCE_PORT
        arguments = ["-sS", "-Pn", "-n", "--source-port", str(source_port)]
        if profile.fragment:
            arguments.append("-f")
        if profile.mtu is not None:
            arguments.extend(["--mtu", str(profile.mtu)])
        if profile.decoys is not None:
            arguments.extend(["-D", f"RND:{profile.decoys}"])
        if profile.timing is not None:
            arguments.append(f"-T{profile.timing}")
        if profile.scan_delay:
            arguments.extend(["--scan-delay", profile.scan_delay])
    if port_spec == "-":
        arguments.append("-p-")
    else:
        arguments.extend(["-p", port_spec])
    arguments.extend(target_args)
    return arguments


def _from_args(args: argparse.Namespace) -> int:
    run_evasion(
        target=_selected_target(args),
        ports=args.ports,
        input_path=args.input,
        latest=args.latest,
        mode=args.mode,
        source_port=args.source_port,
        fragment=args.fragment,
        mtu=args.mtu,
        decoys=args.decoys,
        timing=args.timing,
        scan_delay=args.scan_delay,
    )
    return 0


def _selected_target(args: argparse.Namespace) -> str | None:
    """Return the positional target or ``-t``, rejecting two different values."""
    positional = getattr(args, "target_arg", None)
    flag = getattr(args, "target_flag", None)
    if positional and flag and positional != flag:
        raise EvasionError(
            "Pass the target either as the first argument or with -t, not two different values."
        )
    return flag or positional


def main(argv: list[str] | None = None) -> int:
    """Run firewall mapping or evasion from the command line.

    Nmap and input errors are printed as a single message.
    """
    parser = build_parser()
    err = Console(stderr=True)
    try:
        args = parser.parse_args(argv)
        return int(args.func(args))
    except (NmapError, TargetError, EnumError, EvasionError) as exc:
        err.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        return 1
    except KeyboardInterrupt:
        err.print("\n[yellow]Scan interrupted by the user.[/yellow]")
        return 130


def _require_privileges(mode: str) -> None:
    """Stop before Nmap when raw sockets are unavailable.

    ACK scans, SYN scans, fragmentation, MTU fragmentation, and decoys all
    need an elevated process. There is no connect-scan fallback: ``-sT``
    cannot express ``-sA``, ``-f``, or ``-D``.
    """
    if has_admin_privileges():
        return
    if mode == "firewall-map":
        detail = "TCP ACK scan (-sA) needs raw sockets and administrator or root privileges"
    else:
        detail = (
            "Stealth evasion uses a SYN scan (-sS) and can add -f, --mtu, or -D, "
            "which need raw sockets and administrator or root privileges"
        )
    raise NmapPrivilegeError(f"{detail}. {privilege_hint()}")


def _jobs_from_discovery(
    hosts: list[dict[str, Any]],
    port_spec: str,
    *,
    override_ports: bool,
) -> list[EvasionJob]:
    """Group discovery hosts into jobs that share one port list."""
    live = [host for host in hosts if host.get("ip")]
    if not live:
        return []
    if override_ports:
        return [EvasionJob(port_spec=port_spec, addresses=[str(host["ip"]) for host in live])]

    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for host in live:
        ports = [int(port) for port in host.get("tcp_ports") or []]
        if not ports:
            continue
        spec = ",".join(str(port) for port in ports)
        if spec not in grouped:
            grouped[spec] = []
            order.append(spec)
        grouped[spec].append(str(host["ip"]))
    return [EvasionJob(port_spec=spec, addresses=grouped[spec]) for spec in order]


def _run_jobs(scope: EvasionScope, reports_dir: Path, prefix: str) -> list[NmapRunResult]:
    results: list[NmapRunResult] = []
    width = len(str(len(scope.jobs)))
    for index, job in enumerate(scope.jobs, start=1):
        suffix = ".xml" if len(scope.jobs) == 1 else f"_{index:0{width}d}.xml"
        xml_path = reports_dir / f"{prefix}{suffix}"
        if job.addresses:
            targets = _targets_to_args(job.addresses, reports_dir, f"{prefix}_{index}")
        else:
            targets = job.target_args
        arguments = build_scan_arguments(scope.profile, job.port_spec, targets)
        results.append(run_nmap(arguments, xml_path))
    return results


def _targets_to_args(ips: list[str], reports_dir: Path, prefix: str) -> list[str]:
    """Pass addresses on the command line, or via ``-iL`` when the line is long."""
    if os.name == "nt" and sum(len(ip) + 1 for ip in ips) > 6000:
        list_path = reports_dir / f"{prefix}_targets.txt"
        list_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
        return ["-iL", str(list_path)]
    return list(ips)


def _hosts_from_results(results: list[NmapRunResult]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        for host in parse_nmap_xml(result.xml_path):
            ip = str(host.get("ip") or "")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            ports = [
                {
                    "port": port.get("port"),
                    "protocol": port.get("protocol") or "tcp",
                    "state": str(port.get("state") or "unknown"),
                    "reason": str(port.get("reason") or ""),
                    "service": str(port.get("service") or ""),
                }
                for port in host.get("ports") or []
                if port.get("protocol") in {None, "", "tcp"}
            ]
            ports.sort(key=lambda item: item["port"] if isinstance(item["port"], int) else 0)
            merged.append(
                {
                    "ip": ip,
                    "mac": str(host.get("mac") or ""),
                    "hostnames": list(host.get("hostnames") or []),
                    "status": str(host.get("status") or "unknown"),
                    "ports": ports,
                }
            )
    _sort_hosts(merged)
    return merged


def _state_counts(hosts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in _STATE_ORDER}
    for host in hosts:
        for port in host.get("ports") or []:
            state = str(port.get("state") or "unknown")
            counts[state] = counts.get(state, 0) + 1
    return counts


def _build_report(
    scope: EvasionScope,
    hosts: list[dict[str, Any]],
    results: list[NmapRunResult],
    reports_dir: Path,
    prefix: str,
) -> dict[str, Any]:
    profile = scope.profile
    return {
        "module": "evasion",
        "mode": scope.mode,
        "target": scope.target,
        "input": _relative(scope.input_path) if scope.input_path else None,
        "source_port": profile.source_port,
        "fragment": profile.fragment,
        "mtu": profile.mtu,
        "decoys": profile.decoys,
        "timing": profile.timing,
        "scan_delay": profile.scan_delay,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "state_counts": _state_counts(hosts),
        "hosts": hosts,
        "artifacts": {
            "json": _relative(reports_dir / f"{prefix}.json"),
            "markdown": _relative(reports_dir / f"{prefix}.md"),
            "xml": [_relative(result.xml_path) for result in results],
        },
        "commands": [result.command for result in results],
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
    commands = report.get("commands") or []
    rendered_commands = [shlex.join(command) for command in commands if isinstance(command, list)]
    lines = [
        "# Firewall and evasion",
        "",
        f"- Mode: `{report['mode']}`",
        f"- Target: `{report['target']}`",
        f"- Source port: `{report['source_port'] if report['source_port'] is not None else '-'}`",
        f"- Fragment: {'-f' if report['fragment'] else 'no'}",
        f"- MTU: `{report['mtu'] if report['mtu'] is not None else '-'}`",
        f"- Decoys: `{report['decoys'] if report['decoys'] is not None else '-'}`",
        f"- Timing: `{report['timing'] if report['timing'] is not None else '-'}`",
        f"- Scan delay: `{report['scan_delay'] or '-'}`",
        f"- Generated: {report['generated_at']}",
        "",
        "## Nmap command",
        "",
    ]
    if rendered_commands:
        for command in rendered_commands:
            lines.extend(["```text", command, "```", ""])
    else:
        lines.extend(["No Nmap command was recorded.", ""])
    lines.extend(["## Port states", ""])
    counts: dict[str, int] = report.get("state_counts") or {}
    if counts:
        summary = ", ".join(f"{state} {count}" for state, count in counts.items())
        lines.extend([summary, ""])
    hosts: list[dict[str, Any]] = report["hosts"]
    if not hosts:
        lines.extend(["No hosts were recorded.", ""])
        return "\n".join(lines)
    if report["mode"] == "firewall-map":
        lines.extend(
            [
                "`filtered` means a stateful filter dropped the ACK. "
                "`unfiltered` means the probe got a RST, so the port is reachable "
                "at the filter but open versus closed is still unknown.",
                "",
            ]
        )
    for host in hosts:
        lines.append(f"### {host.get('ip') or 'unknown'}")
        lines.append("")
        ports = host.get("ports") or []
        if not ports:
            lines.extend(["No TCP ports were recorded.", ""])
            continue
        lines.append("| Port | State | Reason | Service |")
        lines.append("| --- | --- | --- | --- |")
        for port in ports:
            lines.append(
                f"| {port.get('port')}/{port.get('protocol')} | {port.get('state')} | "
                f"{port.get('reason') or '-'} | {port.get('service') or '-'} |"
            )
        lines.append("")
    return "\n".join(lines)


def _print_results_table(hosts: list[dict[str, Any]], counts: dict[str, int]) -> None:
    table = Table(title="Port states", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Reason")
    table.add_column("Service")
    listed = 0
    for host in hosts:
        ports = host.get("ports") or []
        if not ports:
            table.add_row(escape(str(host.get("ip") or "")), "-", "-", "-", "-")
            continue
        for port in ports:
            listed += 1
            state = str(port.get("state") or "unknown")
            style = _STATE_STYLE.get(state, "white")
            table.add_row(
                escape(str(host.get("ip") or "")),
                escape(f"{port.get('port')}/{port.get('protocol')}"),
                f"[{style}]{escape(state)}[/{style}]",
                escape(str(port.get("reason") or "-")),
                escape(str(port.get("service") or "-")),
            )
    if hosts:
        console.print(table)
    else:
        console.print("[yellow]No hosts to list.[/yellow]")
    summary = " | ".join(
        f"{state}: {counts.get(state, 0)}" for state in _STATE_ORDER if counts.get(state, 0)
    )
    extra = [
        f"{state}: {count}"
        for state, count in counts.items()
        if state not in _STATE_ORDER and count
    ]
    console.print(
        f"Hosts: {len(hosts)} | Ports: {listed}"
        + (f" | {summary}" if summary else "")
        + (f" | {', '.join(extra)}" if extra else "")
    )


def _safe_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:80] or "target"


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(project_root()).as_posix()
    except ValueError:
        return str(path)


def _sort_hosts(hosts: list[dict[str, Any]]) -> None:
    def sort_key(host: dict[str, Any]) -> tuple[int, Any]:
        ip = str(host.get("ip") or "")
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    hosts.sort(key=sort_key)


if __name__ == "__main__":
    sys.exit(main())
