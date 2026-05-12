"""Aegis-11073-Scanner command-line entry point.

This module wires the :mod:`aegis.parser_11073`, :mod:`aegis.analyzer`, and
:mod:`aegis.reporter` modules together behind a small ``click`` interface::

    aegis scan -f <pcap>          # offline PCAP audit
    aegis live --interface eth0   # (stubbed) live sniffer
    aegis version                 # print version + library info

The ``main`` callable is exposed as the project's console-script entry
point in ``pyproject.toml``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .analyzer import (
    DEFAULT_JITTER_THRESHOLD_MS,
    DEFAULT_PLAINTEXT_SCORE_THRESHOLD,
    TelemetryAnalyzer,
)
from .parser_11073 import parse_pcap
from .reporter import generate_report


_CONSOLE = Console()


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Aegis-11073-Scanner — IEEE 11073 / MBAN cyber-physical auditor.",
)
@click.version_option(__version__, prog_name="aegis")
def main() -> None:
    """Aegis-11073-Scanner CLI root."""


# ---------------------------------------------------------------------------
# `aegis scan`
# ---------------------------------------------------------------------------


@main.command(
    "scan",
    help="Audit an IEEE 11073 PCAP file for plaintext telemetry, missing "
    "MACs, and >8 ms latency anomalies.",
)
@click.option(
    "-f",
    "--file",
    "pcap_file",
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    required=True,
    help="Path to a PCAP / PCAPNG capture containing IEEE 11073 traffic.",
)
@click.option(
    "--jitter-threshold-ms",
    type=float,
    default=DEFAULT_JITTER_THRESHOLD_MS,
    show_default=True,
    help="Inter-arrival jitter (ms) above which a packet is flagged "
    "as a cyber-physical DoS exposure.",
)
@click.option(
    "--plaintext-threshold",
    type=float,
    default=DEFAULT_PLAINTEXT_SCORE_THRESHOLD,
    show_default=True,
    help="Plaintext score (0.0-1.0) above which a payload is treated as "
    "unencrypted biometric / pacing data.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Include per-finding details (entropy scores, nomenclature hits, "
    "median deltas) in the report.",
)
def scan(
    pcap_file: Path,
    jitter_threshold_ms: float,
    plaintext_threshold: float,
    verbose: bool,
) -> None:
    """Run the offline PCAP audit pipeline."""
    _CONSOLE.print(
        f"[bold cyan]aegis[/] scan: dissecting [bright_white]{pcap_file}[/]"
    )

    try:
        packets = parse_pcap(pcap_file)
    except FileNotFoundError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except RuntimeError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(3)

    analyzer = TelemetryAnalyzer(
        jitter_threshold_ms=jitter_threshold_ms,
        plaintext_score_threshold=plaintext_threshold,
    )
    findings = analyzer.analyze(packets)

    generate_report(
        findings,
        source=str(pcap_file),
        packet_count=len(packets),
        console=_CONSOLE,
        verbose=verbose,
    )

    sys.exit(1 if any(f.severity == "CRITICAL" for f in findings) else 0)


# ---------------------------------------------------------------------------
# `aegis live`  (stub)
# ---------------------------------------------------------------------------


@main.command(
    "live",
    help="Sniff an interface for live IEEE 11073 traffic. STUBBED in MVP.",
)
@click.option(
    "--interface",
    "-i",
    required=True,
    help="Network interface to sniff (e.g. eth0, wlan0, bnep0).",
)
def live(interface: str) -> None:
    """Stubbed live sniffer.

    Live medical-network sniffing is an *extremely* sensitive operation. It
    requires CAP_NET_RAW / root, signed FDA/IRB authorization, and a
    documented patient-safety contingency. This MVP intentionally refuses
    to start a live capture and instead prints the legal pre-flight check.
    """
    _CONSOLE.print(
        "[bold red]REFUSED[/] - live medical sniffing is disabled in this build."
    )
    _CONSOLE.print()
    _CONSOLE.print(
        f"[yellow]Interface requested:[/] [bright_white]{interface}[/]"
    )
    _CONSOLE.print()
    _CONSOLE.print(
        "[bold]Pre-flight requirements before enabling live mode:[/]\n"
        "  1. Root / CAP_NET_RAW privileges on the auditing host.\n"
        "  2. Documented FDA 21 CFR Part 820 change-control approval.\n"
        "  3. IRB / ethics-board sign-off for any in-vivo capture.\n"
        "  4. A written patient-safety abort procedure with on-call clinician.\n"
        "  5. RF spectrum coordination if intercepting WMTS / MICS bands."
    )
    _CONSOLE.print()
    _CONSOLE.print(
        "[dim]Re-build with --enable-live (planned) only after the above are "
        "in writing.[/]"
    )
    sys.exit(64)  # EX_USAGE


# ---------------------------------------------------------------------------
# `aegis version`
# ---------------------------------------------------------------------------


@main.command("version", help="Print version + dependency banner.")
def version() -> None:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    _CONSOLE.print(f"[bold]aegis-11073-scanner[/] [bright_white]{__version__}[/]")
    for dep in ("scapy", "rich", "click"):
        try:
            _CONSOLE.print(f"  {dep:<6} {_pkg_version(dep)}")
        except PackageNotFoundError:
            _CONSOLE.print(f"  {dep:<6} [red]not installed[/]")


if __name__ == "__main__":  # pragma: no cover
    main()
