"""Run Nmap through ``subprocess`` without invoking a shell.

The runner checks that the ``nmap`` binary is on ``PATH``, refuses scan
techniques that need raw sockets when the process is not elevated, and
always writes the raw report with ``-oX`` under ``reports/``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Scan techniques that need raw sockets or an elevated process.
# Letters match Nmap's ``-s<letter>`` scan types (SYN, UDP, ACK, IP protocol,
# and the TCP null/FIN/Xmas family). Connect scans (``-sT``) and version
# detection (``-sV``) are intentionally excluded.
_PRIVILEGED_SCAN_LETTERS = frozenset("SUAWMNFXO")
_PRIVILEGED_EXACT = frozenset({"-O", "-f"})
_PRIVILEGED_PREFIXES = (
    "-D",
    "-PE",
    "-PM",
    "-PP",
    "-PO",
    "-PR",
    "-PS",
    "-PA",
    "-PU",
    "-PY",
)

_PRIVILEGE_MARKERS = (
    "requires root privileges",
    "requires administrator",
    "operation not permitted",
    "you requested a scan type which requires root",
    "couldn't open a raw socket",
    "npcap",
    "winpcap",
)


class NmapError(Exception):
    """Base error for failures while preparing or running Nmap."""


class NmapNotFoundError(NmapError):
    """The ``nmap`` executable is not available on ``PATH``."""


class NmapPrivilegeError(NmapError):
    """The requested technique needs administrator or root privileges."""


class NmapExecutionError(NmapError):
    """Nmap exited with a non-zero status or did not write its XML report."""


@dataclass(frozen=True)
class NmapRunResult:
    """Outcome of a single Nmap invocation."""

    command: list[str]
    return_code: int
    xml_path: Path
    stdout: str


def project_root() -> Path:
    """Return the repository root (parent of the ``core`` package)."""
    return Path(__file__).resolve().parent.parent


def ensure_reports_dir() -> Path:
    """Create the ``reports`` directory at the project root and return it.

    Scan artifacts stay in this folder so they can be git-ignored. The
    directory is created with ``os.makedirs(..., exist_ok=True)``.
    """
    reports_dir = project_root() / "reports"
    try:
        os.makedirs(reports_dir, exist_ok=True)
    except OSError as exc:
        raise NmapError(
            f"Could not create the reports directory '{reports_dir}': {exc}"
        ) from exc
    return reports_dir


def nmap_binary() -> str:
    """Resolve the Nmap executable on ``PATH``.

    Raises:
        NmapNotFoundError: ``nmap`` is not installed or not reachable.
    """
    binary = shutil.which("nmap")
    if binary is None:
        raise NmapNotFoundError(
            "Nmap is not installed or not available on PATH. "
            "Install Nmap and open a new terminal so the `nmap` executable can be found."
        )
    return binary


def has_admin_privileges() -> bool:
    """Return whether the current process can use raw-socket scan types.

    On Windows this checks for an elevated token, not merely membership of
    the Administrators group. On Unix it checks for an effective uid of 0.
    """
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def privilege_hint() -> str:
    """Return a short instruction for how to re-run the process elevated."""
    if os.name == "nt":
        return "Open the terminal as Administrator and run the command again."
    return "Re-run the command with sudo or as root."


def command_requires_privileges(arguments: list[str]) -> bool:
    """Return whether any Nmap argument needs administrator or root rights.

    Covers the techniques called out by the project standard (``-sS``,
    ``-sU``, ``-O``, ``-sA``, ``-f``, ``-D``) plus raw host-discovery probes
    (``-PE``, ``-PR``, ``-PS``, and the related ``-P*`` family).
    """
    for arg in arguments:
        if arg in _PRIVILEGED_EXACT:
            return True
        if any(arg.startswith(prefix) for prefix in _PRIVILEGED_PREFIXES):
            return True
        if _scan_type_needs_privileges(arg):
            return True
    return False


def run_nmap(scan_args: list[str], xml_path: Path) -> NmapRunResult:
    """Execute Nmap and store the raw XML report at ``xml_path``.

    Arguments are passed as a list (``shell=False``). ``-oX`` is appended by
    this function so every scan leaves a parseable artifact in ``reports/``.

    Args:
        scan_args: Nmap options and targets, without the binary and without
            ``-oX``.
        xml_path: Destination for the XML report. Parent directories are
            created when missing.

    Returns:
        The command that ran, its exit code, the XML path, and captured output.

    Raises:
        NmapNotFoundError: Nmap is not on ``PATH``.
        NmapPrivilegeError: The arguments need elevation and the process
            does not have it, or Nmap itself rejected the scan for that reason.
        NmapExecutionError: Nmap failed or did not produce the XML report.
        NmapError: An argument is empty or contains a newline or NUL.
    """
    _validate_scan_args(scan_args)
    if command_requires_privileges(scan_args) and not has_admin_privileges():
        raise NmapPrivilegeError(
            "This Nmap command uses a technique that needs administrator or "
            f"root privileges ({_privileged_flags(scan_args)}). {privilege_hint()}"
        )

    binary = nmap_binary()
    try:
        os.makedirs(xml_path.parent, exist_ok=True)
    except OSError as exc:
        raise NmapError(f"Could not create '{xml_path.parent}': {exc}") from exc

    command = [binary, *scan_args, "-oX", str(xml_path)]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except OSError as exc:
        raise NmapExecutionError(f"Failed to start Nmap: {exc}") from exc

    if process.stdout is None:
        process.kill()
        raise NmapExecutionError("Failed to capture Nmap output.")

    chunks: list[str] = []
    try:
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            chunks.append(line)
        return_code = process.wait()
    except KeyboardInterrupt:
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        raise

    combined = "".join(chunks)
    if return_code != 0:
        tail = _output_tail(combined)
        if _looks_like_privilege_failure(combined):
            raise NmapPrivilegeError(
                "Nmap refused the scan because raw sockets are unavailable. "
                f"{privilege_hint()}\n{tail}"
            )
        raise NmapExecutionError(
            f"Nmap exited with status {return_code}.\n{tail}"
        )

    if not xml_path.is_file() or xml_path.stat().st_size == 0:
        raise NmapExecutionError(
            f"Nmap finished without writing an XML report at '{xml_path}'."
        )

    return NmapRunResult(
        command=command,
        return_code=return_code,
        xml_path=xml_path,
        stdout=combined,
    )


def _scan_type_needs_privileges(arg: str) -> bool:
    """Return whether a ``-s<letters>`` argument needs raw sockets."""
    if not arg.startswith("-s") or arg.startswith("--") or len(arg) < 3:
        return False
    letters = arg[2:]
    if not letters.isalpha():
        return False
    return any(letter in _PRIVILEGED_SCAN_LETTERS for letter in letters.upper())


def _privileged_flags(arguments: list[str]) -> str:
    """Return the subset of arguments that triggered the privilege check."""
    matched = [
        arg
        for arg in arguments
        if arg in _PRIVILEGED_EXACT
        or any(arg.startswith(prefix) for prefix in _PRIVILEGED_PREFIXES)
        or _scan_type_needs_privileges(arg)
    ]
    return ", ".join(matched) if matched else "raw-socket technique"


def _validate_scan_args(arguments: list[str]) -> None:
    if not arguments:
        raise NmapError("Refusing to run Nmap without scan arguments.")
    for arg in arguments:
        if not isinstance(arg, str) or arg == "" or "\x00" in arg or "\n" in arg or "\r" in arg:
            raise NmapError("Refusing to run Nmap with an empty or malformed argument.")


def _looks_like_privilege_failure(output: str) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in _PRIVILEGE_MARKERS)


def _output_tail(output: str, lines: int = 15) -> str:
    if not output.strip():
        return "(Nmap produced no output.)"
    kept = output.strip().splitlines()[-lines:]
    return "\n".join(kept)
