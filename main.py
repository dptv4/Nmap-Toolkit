"""Unified CLI for Nmap-Toolkit.

Run ``python main.py discovery --help`` for the host-discovery module.
Further reconnaissance phases register additional subcommands here.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.markup import escape

from core.runner import NmapError
from modules import discovery
from modules.discovery import TargetError

console = Console(stderr=True)

_DESCRIPTION = """\
Nmap-Toolkit — CPTS reconnaissance workflow.

Authorized use only: lab environments (Hack The Box, CPTS) and audits you
are explicitly allowed to perform.

modules:
  discovery    Live host discovery and a fast all-TCP-port scan
"""

_EPILOG = """\
examples:
  python main.py discovery -t 10.10.10.0/24 --method arp-icmp
  python main.py discovery -t 10.10.10.10 --method syn
  python main.py discovery -t 10.10.10.10 --method skip
"""


def build_parser() -> argparse.ArgumentParser:
    """Build the root argument parser and register toolkit modules."""
    parser = argparse.ArgumentParser(
        prog="nmap-toolkit",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="module", required=True, metavar="module")
    discovery.register(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch the selected module.

    Nmap and target errors are printed as a single message. Unexpected
    failures still raise so they can be debugged.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return int(handler(args))
    except (NmapError, TargetError) as exc:
        console.print(f"[bold red]Error:[/bold red] {escape(str(exc))}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by the user.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
