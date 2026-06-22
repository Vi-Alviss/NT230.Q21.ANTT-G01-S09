from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from models import DetectionReport, RiskLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_color(level: RiskLevel) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(level.value, "white")


def _conf_color(conf: str) -> str:
    return {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(conf, "white")


# ---------------------------------------------------------------------------
# Rich console renderer
# ---------------------------------------------------------------------------

def render_report(console: Console, report: DetectionReport) -> None:
    """Render one detection report to console."""
    color = _risk_color(report.risk_level)

    # ── Summary table ────────────────────────────────────────────────────────
    summary = Table(title=f"[bold]Analysis:[/bold] {report.file_path}", box=box.ROUNDED)
    summary.add_column("Field",  style="cyan", no_wrap=True)
    summary.add_column("Value",  style="white")
    summary.add_row("File size",         f"{report.file_size:,} bytes")
    summary.add_row("File entropy",      f"{report.file_entropy:.4f}")
    summary.add_row("Printable strings", str(report.printable_string_count))
    summary.add_row("Import count",      str(report.import_report.total_imports))
    summary.add_row("Packers found",     str(len(report.packer_matches)) or "0")
    summary.add_row("Score",             str(report.score))
    summary.add_row("Risk",              f"[{color}]{report.risk_level.value}[/{color}]")
    console.print(summary)

    # ── .NET obfuscator section ──────────────────────────────────────────────
    dn = report.dotnet_report
    if dn and dn.is_dotnet:
        dotnet_tbl = Table(title=".NET Assembly Analysis", box=box.ROUNDED)
        dotnet_tbl.add_column("Field",  style="cyan", no_wrap=True)
        dotnet_tbl.add_column("Value",  style="white")
        dotnet_tbl.add_row("CLR Version",    dn.clr_version or "unknown")
        dotnet_tbl.add_row("Obfuscators",    ", ".join(dn.obfuscators_found) or "None detected")
        dotnet_tbl.add_row("Confidence",     dn.confidence)
        dotnet_tbl.add_row("Signals count",  str(len(dn.detection_signals)))
        console.print(dotnet_tbl)

        if dn.detection_signals:
            for sig in dn.detection_signals:
                console.print(f"  [dim]•[/dim] {sig}")

    # ── Packer identification table ──────────────────────────────────────────
    if report.packer_matches:
        packers_tbl = Table(title="Identified Packers", box=box.ROUNDED)
        packers_tbl.add_column("Packer",      style="magenta")
        packers_tbl.add_column("Confidence",  justify="center")
        packers_tbl.add_column("MITRE ATT&CK")
        packers_tbl.add_column("Detection signals")
        for pm in report.packer_matches:
            cc = _conf_color(pm.confidence)
            packers_tbl.add_row(
                pm.packer_name,
                f"[{cc}]{pm.confidence}[/{cc}]",
                pm.mitre_ref,
                " | ".join(pm.detection_signals),
            )
        console.print(packers_tbl)

    # ── PE Sections table ────────────────────────────────────────────────────
    sections_tbl = Table(title="PE Sections", box=box.ROUNDED)
    sections_tbl.add_column("#",          style="cyan")
    sections_tbl.add_column("Name")
    sections_tbl.add_column("Entropy",    justify="right")
    sections_tbl.add_column("RawSize",    justify="right")
    sections_tbl.add_column("VirtSize",   justify="right")
    sections_tbl.add_column("Suspicious reasons")
    for sr in report.section_reports:
        sections_tbl.add_row(
            str(sr.index),
            sr.name,
            f"{sr.entropy:.4f}",
            f"{sr.size_of_raw_data:,}",
            f"{sr.virtual_size:,}",
            ", ".join(sr.suspicious_reasons) or "-",
        )
    console.print(sections_tbl)

    # ── Signals table ────────────────────────────────────────────────────────
    signals_tbl = Table(title="Heuristic Signals", box=box.ROUNDED)
    signals_tbl.add_column("Code",        style="cyan")
    signals_tbl.add_column("Description")
    signals_tbl.add_column("Weight",      justify="right")
    if report.signals:
        for s in report.signals:
            signals_tbl.add_row(s.code, s.description, str(s.weight))
    else:
        signals_tbl.add_row("-", "No suspicious signal", "0")
    console.print(signals_tbl)

    # ── Suspicious API list ──────────────────────────────────────────────────
    if report.import_report.suspicious_apis:
        console.print(
            "[yellow]Suspicious APIs:[/yellow] "
            + ", ".join(report.import_report.suspicious_apis)
        )


def render_reports(reports: list[DetectionReport], html_output_path: str | None = None) -> None:
    """Render all reports to console and optionally export HTML."""
    record = bool(html_output_path)
    console = Console(record=record)

    for idx, report in enumerate(reports):
        if idx > 0:
            console.rule()
        render_report(console, report)

    # ── HTML export ──────────────────────────────────────────────────────────
    if html_output_path:
        # Rich saves terminal-colored HTML — wrap in a nicer shell
        raw_html = console.export_html(clear=False)
        final_html = _wrap_html_report(raw_html, reports)
        out = Path(html_output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(final_html, encoding="utf-8")
        print(f"[INFO] HTML report saved → {out}")


# ---------------------------------------------------------------------------
# HTML report wrapper  (clean dark-theme shell around Rich output)
# ---------------------------------------------------------------------------

def _risk_badge(level: RiskLevel) -> str:
    colors = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
    c = colors.get(level.value, "#888")
    return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700">{level.value}</span>'


def _wrap_html_report(rich_html_body: str, reports: list[DetectionReport]) -> str:
    now       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    n_high    = sum(1 for r in reports if r.risk_level == RiskLevel.HIGH)
    n_medium  = sum(1 for r in reports if r.risk_level == RiskLevel.MEDIUM)
    n_low     = sum(1 for r in reports if r.risk_level == RiskLevel.LOW)
    total     = len(reports)

    # build packer summary cards
    all_packers: dict[str, int] = {}
    for r in reports:
        for pm in r.packer_matches:
            all_packers[pm.packer_name] = all_packers.get(pm.packer_name, 0) + 1

    packer_cards = ""
    for pname, cnt in sorted(all_packers.items()):
        packer_cards += (
            f'<div class="card pcard">'
            f'<div class="pname">{pname}</div>'
            f'<div class="pcnt">{cnt} file{"s" if cnt > 1 else ""}</div>'
            f'</div>'
        )
    if not packer_cards:
        packer_cards = '<p style="color:#888;font-style:italic">No known packers identified.</p>'

    # strip Rich's own <html>/<body> wrapper — keep only the inner pre block
    import re
    inner = re.search(r"(<pre[^>]*>.*?</pre>)", rich_html_body, re.DOTALL)
    rich_pre = inner.group(1) if inner else rich_html_body

    file_rows = "".join(
        f"<tr>"
        f"<td>{Path(r.file_path).name}</td>"
        f"<td>{r.file_size:,}</td>"
        f"<td>{r.file_entropy:.4f}</td>"
        f"<td>{', '.join(p.packer_name for p in r.packer_matches) or '—'}</td>"
        f"<td>{_risk_badge(r.risk_level)}</td>"
        f"<td>{r.score}</td>"
        f"</tr>"
        for r in reports
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Binary Packing Detection Report</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3e;
    --text: #e2e8f0; --muted: #64748b;
    --high: #ef4444; --med: #f59e0b; --low: #22c55e; --info: #3b82f6;
    --accent: #7c3aed;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; }}
  header {{
    background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
    border-bottom: 1px solid var(--accent);
    padding: 2rem 3rem;
  }}
  header h1 {{ font-size: 1.6rem; color: #a78bfa; letter-spacing: .05em; }}
  header .sub {{ color: var(--muted); font-size: .8rem; margin-top: .3rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 3rem; }}
  .stats-row {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.5rem; min-width: 140px; flex: 1;
  }}
  .stat-card .num {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .lbl {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; }}
  .high   {{ color: var(--high); }}
  .medium {{ color: var(--med); }}
  .low    {{ color: var(--low); }}
  .blue   {{ color: var(--info); }}
  section {{ margin-bottom: 2.5rem; }}
  section h2 {{
    font-size: .9rem; text-transform: uppercase; letter-spacing: .1em;
    color: var(--muted); border-bottom: 1px solid var(--border);
    padding-bottom: .5rem; margin-bottom: 1rem;
  }}
  .packer-grid {{ display: flex; gap: .75rem; flex-wrap: wrap; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1.25rem; }}
  .pcard .pname {{ color: #a78bfa; font-weight: 700; font-size: .95rem; }}
  .pcard .pcnt  {{ color: var(--muted); font-size: .75rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
  th {{ background: var(--surface); color: var(--muted); text-transform: uppercase;
        font-size: .7rem; letter-spacing: .06em; padding: .6rem .8rem; text-align: left; }}
  td {{ padding: .55rem .8rem; border-bottom: 1px solid var(--border); color: var(--text); }}
  tr:hover td {{ background: rgba(124,58,237,.06); }}
  .rich-output {{
    background: #0d0d0d; border: 1px solid var(--border); border-radius: 8px;
    padding: 1.5rem; overflow-x: auto; font-size: .78rem; line-height: 1.5;
  }}
  footer {{ text-align: center; color: var(--muted); font-size: .72rem;
            padding: 2rem; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>🔍 Binary Packing Detection Report</h1>
  <div class="sub">Generated: {now} &nbsp;|&nbsp; Tool: BinaryPackingDetector v2.0 &nbsp;|&nbsp; MITRE ATT&CK T1027</div>
</header>
<div class="container">

  <!-- Stats -->
  <div class="stats-row">
    <div class="stat-card"><div class="num blue">{total}</div><div class="lbl">Files Analyzed</div></div>
    <div class="stat-card"><div class="num high">{n_high}</div><div class="lbl">HIGH Risk</div></div>
    <div class="stat-card"><div class="num medium">{n_medium}</div><div class="lbl">MEDIUM Risk</div></div>
    <div class="stat-card"><div class="num low">{n_low}</div><div class="lbl">LOW Risk</div></div>
    <div class="stat-card"><div class="num" style="color:var(--accent)">{len(all_packers)}</div><div class="lbl">Packer Families</div></div>
  </div>

  <!-- Packer Summary -->
  <section>
    <h2>Identified Packer Families</h2>
    <div class="packer-grid">{packer_cards}</div>
  </section>

  <!-- File Summary Table -->
  <section>
    <h2>File Summary</h2>
    <table>
      <tr>
        <th>File</th><th>Size (B)</th><th>Entropy</th>
        <th>Packers</th><th>Risk</th><th>Score</th>
      </tr>
      {file_rows}
    </table>
  </section>

  <!-- Detailed Rich Output -->
  <section>
    <h2>Detailed Analysis</h2>
    <div class="rich-output">
      {rich_pre}
    </div>
  </section>

</div>
<footer>Binary Packing Detector — Academic research tool — MITRE ATT&CK T1027</footer>
</body>
</html>"""
