"""Rich terminal reporting for Aegis-11073-Scanner.

The :func:`generate_report` function renders an audit table that is
deliberately styled to look like the output of a serious commercial
auditing tool — colour-coded severities, eCVSS scores, a banner, and
a verdict footer.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.box import HEAVY_HEAD
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import Finding, Severity


SEVERITY_STYLE: dict[Severity, str] = {
    "INFO": "dim",
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "bright_red",
    "CRITICAL": "bold white on red",
}

SEVERITY_RANK: dict[Severity, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _banner(console: Console, source: str, packet_count: int) -> None:
    """Render the Aegis banner at the top of the report."""
    title = Text("AEGIS-11073-SCANNER", style="bold bright_white")
    subtitle = Text(
        "IEEE 11073-20601 / 104xx Cyber-Physical Audit Report",
        style="italic dim",
    )
    body = Text.assemble(
        title, "\n", subtitle, "\n\n",
        ("source: ", "dim"), (source, "bright_white"), "\n",
        ("packets analysed: ", "dim"), (str(packet_count), "bright_white"),
    )
    console.print(Panel(body, border_style="red", expand=False))


def _verdict_footer(console: Console, findings: list[Finding]) -> None:
    """Print the closing verdict + per-severity counts."""
    counts: Counter[Severity] = Counter(f.severity for f in findings)
    has_critical = counts.get("CRITICAL", 0) > 0

    if not findings:
        console.print(
            Panel(
                Text(
                    "No vulnerabilities detected within the configured "
                    "thresholds. Manual review still recommended for any "
                    "life-critical deployment.",
                    style="green",
                ),
                border_style="green",
                title="VERDICT",
            )
        )
        return

    breakdown = "  ".join(
        f"[{SEVERITY_STYLE[sev]}]{sev}={counts.get(sev, 0)}[/]"
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    verdict_text = Text.from_markup(
        f"Findings by severity:  {breakdown}\n\n"
        + (
            "[bold white on red] DEVICE FAILS CYBER-PHYSICAL SAFETY "
            "REVIEW [/] — at least one CRITICAL exposure detected. "
            "Halt clinical deployment pending remediation."
            if has_critical
            else "[yellow]Non-critical exposures detected. Remediate "
            "before production rollout.[/]"
        )
    )
    console.print(
        Panel(
            verdict_text,
            border_style="red" if has_critical else "yellow",
            title="VERDICT",
        )
    )


def generate_report(
    findings: Iterable[Finding],
    *,
    source: str = "<unknown>",
    packet_count: int = 0,
    console: Console | None = None,
    verbose: bool = False,
) -> None:
    """Render the audit findings as a rich-formatted terminal report."""
    console = console or Console()
    findings_list = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], f.timestamp),
    )

    _banner(console, source=source, packet_count=packet_count)

    table = Table(
        title="Aegis Vulnerability Findings",
        title_style="bold bright_white",
        box=HEAVY_HEAD,
        header_style="bold bright_white on red",
        show_lines=True,
        expand=True,
    )
    table.add_column("Timestamp", style="dim", no_wrap=True, width=14)
    table.add_column("APDU Type", style="cyan", no_wrap=True, width=12)
    table.add_column("Vulnerability", style="white", overflow="fold")
    table.add_column("Severity (eCVSS)", no_wrap=True, width=20)
    table.add_column("Remediation", style="green", overflow="fold")

    for finding in findings_list:
        ts, apdu, vuln, sev_label, remediation = finding.as_row()
        severity_text = Text(sev_label, style=SEVERITY_STYLE[finding.severity])
        vuln_cell = vuln
        if verbose and finding.details:
            vuln_cell = f"{vuln}\n[dim]{finding.details}[/]"
        table.add_row(
            ts,
            apdu,
            Text.from_markup(vuln_cell) if verbose else vuln,
            severity_text,
            remediation,
        )

    console.print(table)
    _verdict_footer(console, findings_list)


__all__ = ["generate_report", "SEVERITY_STYLE"]
