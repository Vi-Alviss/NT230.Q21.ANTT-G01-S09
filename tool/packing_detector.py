from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import pefile

from analyzers.entropy import calculate_section_entropies, count_printable_strings, shannon_entropy
from analyzers.imports import (
    analyze_imports,
    CRYPTO_APIS,
    EXEC_APIS,
    WRITE_APIS,
)
from analyzers.pe_sections import analyze_sections
from analyzers.signatures import (
    detect_packer_signatures,
    detect_packer_signature,
    check_section_names_for_packers,
    PACKER_MITRE,
)
from analyzers.dotnet import analyze_dotnet
from models import DetectionReport, DotNetReport, PackerInfo, RiskLevel, Signal
from reporter import render_reports


SUPPORTED_EXTENSIONS = {".exe", ".dll", ".sys", ".bin"}


def _collect_targets(target_path: Path) -> list[Path]:
    if not target_path.exists():
        raise FileNotFoundError(f"Target does not exist: {target_path}")
    if target_path.is_file():
        return [target_path]
    files: list[Path] = []
    for item in target_path.rglob("*"):
        if item.is_file() and item.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(item)
    return sorted(files)


def _score_to_risk(score: int) -> RiskLevel:
    # LOW  : 0–3   → no strong evidence, likely clean or false-positive noise
    # MEDIUM: 4–9  → suspicious signals present but needs more evidence
    # HIGH : 10+   → at least 2 independent evidence types, likely packed
    if score <= 3:
        return RiskLevel.LOW
    elif score <= 9:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.HIGH


def analyze_file(file_path: Path) -> DetectionReport:
    """Analyze one binary file and return a detection report."""
    data = file_path.read_bytes()
    if len(data) < 64:
        raise ValueError("File too small to analyze reliably (<64 bytes).")

    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    file_entropy            = shannon_entropy(data)
    section_entropies       = calculate_section_entropies(pe)
    section_reports         = analyze_sections(pe, section_entropies)
    import_report           = analyze_imports(pe)
    printable_string_count  = count_printable_strings(data)

    # ── Multi-packer detection ───────────────────────────────────────────────
    packer_matches_raw      = detect_packer_signatures(data)
    section_names           = [s.name for s in section_reports]
    section_packer_matches  = check_section_names_for_packers(section_names)

    # merge (section hits may add packers not caught by byte scan)
    seen_names = {m.packer_name for m in packer_matches_raw}
    for spm in section_packer_matches:
        if spm.packer_name not in seen_names:
            packer_matches_raw.append(spm)
            seen_names.add(spm.packer_name)
        else:
            # merge signals into existing match
            for pm in packer_matches_raw:
                if pm.packer_name == spm.packer_name:
                    pm.signals.extend(spm.signals)

    # Convert to model objects
    packer_infos: list[PackerInfo] = [
        PackerInfo(
            packer_name=m.packer_name,
            confidence=m.confidence,
            mitre_ref=m.mitre_ref,
            detection_signals=m.signals,
        )
        for m in packer_matches_raw
    ]

    # ── .NET obfuscator detection (ConfuserEx, NetReactor) ──────────────────
    dotnet_report = analyze_dotnet(pe, data)

    if dotnet_report.is_dotnet:
        for obf_name in dotnet_report.obfuscators_found:
            if obf_name not in seen_names:
                packer_infos.append(PackerInfo(
                    packer_name=obf_name,
                    confidence=dotnet_report.confidence,
                    mitre_ref=PACKER_MITRE.get(obf_name, "T1027.002"),
                    detection_signals=dotnet_report.detection_signals,
                ))
                seen_names.add(obf_name)

    # Legacy compat field
    signature_hit = packer_matches_raw[0].packer_name if packer_matches_raw else None

    signals: list[Signal] = []

    # ── Entropy signals ──────────────────────────────────────────────────────
    if file_entropy > 7.0:
        signals.append(Signal(
            code="ENTROPY_FILE_HIGH",
            description=f"File entropy {file_entropy:.3f} > 7.0",
            weight=3,
        ))

    high_entropy_sections = [s for s in section_reports if s.entropy > 7.2]
    if high_entropy_sections:
        signals.append(Signal(
            code="ENTROPY_SECTION_HIGH",
            description=f"{len(high_entropy_sections)} section(s) entropy > 7.2",
            weight=3,
        ))

    # ── Section anomaly signals ──────────────────────────────────────────────
    suspicious_section_names = [
        s.name for s in section_reports
        if "suspicious section name" in s.suspicious_reasons
    ]
    if suspicious_section_names:
        signals.append(Signal(
            code="SECTION_NAME_SUSPICIOUS",
            description="Suspicious section names: " + ", ".join(sorted(set(suspicious_section_names))),
            weight=4,
        ))

    raw_virtual_anomalies = [
        s for s in section_reports
        if "raw size is zero but virtual size > 0" in s.suspicious_reasons
    ]
    if raw_virtual_anomalies:
        signals.append(Signal(
            code="SECTION_SIZE_ANOMALY",
            description=f"{len(raw_virtual_anomalies)} section(s): raw=0, virtual>0",
            weight=2,
        ))

    # ── Import signals ───────────────────────────────────────────────────────
    if import_report.total_imports < 3:
        signals.append(Signal(
            code="IMPORT_COUNT_LOW",
            description=f"Import count low ({import_report.total_imports} < 3)",
            weight=2,
        ))

    lowered     = import_report.all_imports_lower
    crypto_hits = lowered & CRYPTO_APIS
    exec_hits   = lowered & EXEC_APIS
    write_hits  = lowered & WRITE_APIS

    if crypto_hits and exec_hits:
        signals.append(Signal(
            code="CRYPTO_EXEC_COMBO",
            description=(
                "Decrypt+Execute API combo — T1140+T1106: "
                + ", ".join(sorted(crypto_hits | exec_hits))
            ),
            weight=4,
        ))

    if write_hits and exec_hits:
        signals.append(Signal(
            code="DROP_EXEC_PATTERN",
            description=(
                "WriteFile+CreateProcess pattern — T1036: "
                + ", ".join(sorted(write_hits | exec_hits))
            ),
            weight=3,
        ))

    # ── String / signature signals ───────────────────────────────────────────
    if printable_string_count < 10:
        signals.append(Signal(
            code="PRINTABLE_STRINGS_LOW",
            description=f"Printable strings low ({printable_string_count} < 10)",
            weight=1,
        ))

    if packer_infos:
        high_conf = [p for p in packer_infos if p.confidence == "HIGH"]
        weight    = 4 if high_conf else 2
        names     = ", ".join(p.packer_name for p in packer_infos)
        signals.append(Signal(
            code="PACKER_SIGNATURE_HIT",
            description=f"Packer identified: {names}",
            weight=weight,
        ))

    # ── .NET obfuscator signals ──────────────────────────────────────────────
    if dotnet_report.is_dotnet and dotnet_report.obfuscators_found:
        conf  = dotnet_report.confidence
        names = ", ".join(dotnet_report.obfuscators_found)
        weight = 4 if conf == "HIGH" else 2
        signals.append(Signal(
            code="DOTNET_OBFUSCATOR_HIT",
            description=f".NET obfuscator detected ({conf}): {names}",
            weight=weight,
        ))

    score      = sum(s.weight for s in signals)
    risk_level = _score_to_risk(score)

    return DetectionReport(
        file_path=str(file_path),
        file_size=len(data),
        file_entropy=file_entropy,
        printable_string_count=printable_string_count,
        section_reports=section_reports,
        import_report=import_report,
        signature_hit=signature_hit,
        signals=signals,
        score=score,
        risk_level=risk_level,
        packer_matches=packer_infos,
        dotnet_report=dotnet_report,
    )


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def _report_to_dict(report: DetectionReport) -> dict:
    return {
        "file_path":             report.file_path,
        "file_size":             report.file_size,
        "file_entropy":          round(report.file_entropy, 4),
        "printable_string_count": report.printable_string_count,
        "risk_level":            report.risk_level.value,
        "score":                 report.score,
        "signature_hit":         report.signature_hit,
        "packer_matches": [
            {
                "packer_name":       pm.packer_name,
                "confidence":        pm.confidence,
                "mitre_ref":         pm.mitre_ref,
                "detection_signals": pm.detection_signals,
            }
            for pm in report.packer_matches
        ],
        "signals": [
            {"code": s.code, "description": s.description, "weight": s.weight}
            for s in report.signals
        ],
        "sections": [
            {
                "index":              sr.index,
                "name":               sr.name,
                "entropy":            round(sr.entropy, 4),
                "size_of_raw_data":   sr.size_of_raw_data,
                "virtual_size":       sr.virtual_size,
                "suspicious_reasons": sr.suspicious_reasons,
            }
            for sr in report.section_reports
        ],
        "imports": {
            "total_imports":   report.import_report.total_imports,
            "suspicious_apis": report.import_report.suspicious_apis,
        },
        "dotnet_analysis": (
            {
                "is_dotnet":          report.dotnet_report.is_dotnet,
                "clr_version":        report.dotnet_report.clr_version,
                "obfuscators_found":  report.dotnet_report.obfuscators_found,
                "confidence":         report.dotnet_report.confidence,
                "detection_signals":  report.dotnet_report.detection_signals,
            }
            if report.dotnet_report else None
        ),
    }


def export_json(reports: list[DetectionReport], output_path: str) -> None:
    payload = {
        "tool":       "BinaryPackingDetector",
        "version":    "2.0.0",
        "generated":  datetime.utcnow().isoformat() + "Z",
        "total_files": len(reports),
        "summary": {
            "HIGH":   sum(1 for r in reports if r.risk_level == RiskLevel.HIGH),
            "MEDIUM": sum(1 for r in reports if r.risk_level == RiskLevel.MEDIUM),
            "LOW":    sum(1 for r in reports if r.risk_level == RiskLevel.LOW),
        },
        "results": [_report_to_dict(r) for r in reports],
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[INFO] JSON report saved → {out}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect packed/obfuscated PE binaries — static heuristics + 13 packer signatures."
    )
    parser.add_argument("target", help="Path to one file or directory")
    parser.add_argument("--html", help="Export HTML report to this path")
    parser.add_argument("--json", help="Export JSON report to this path", dest="json_out")
    return parser.parse_args()


def main() -> int:
    args  = parse_args()
    target = Path(args.target)

    try:
        candidates = _collect_targets(target)
    except FileNotFoundError as error:
        print(f"[ERROR] {error}")
        return 1

    if not candidates:
        print("[WARN] No candidate binaries found.")
        return 1

    reports: list[DetectionReport] = []
    for file_path in candidates:
        try:
            reports.append(analyze_file(file_path))
        except pefile.PEFormatError:
            print(f"[WARN] Skip non-PE file: {file_path}")
        except ValueError as error:
            print(f"[WARN] Skip {file_path}: {error}")
        except Exception as error:
            print(f"[WARN] Unexpected error for {file_path}: {error}")

    if not reports:
        print("[WARN] No analyzable PE files found.")
        return 1

    render_reports(reports, html_output_path=args.html)

    if args.json_out:
        export_json(reports, args.json_out)

    return 1 if any(r.risk_level == RiskLevel.HIGH for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
