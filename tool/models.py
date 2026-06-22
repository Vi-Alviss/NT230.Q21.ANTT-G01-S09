from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


@dataclass
class Signal:
    code: str
    description: str
    weight: int


@dataclass
class SectionReport:
    index: int
    name: str
    entropy: float
    size_of_raw_data: int
    virtual_size: int
    suspicious_reasons: list[str] = field(default_factory=list)


@dataclass
class ImportReport:
    total_imports: int
    suspicious_apis: list[str] = field(default_factory=list)
    all_imports_lower: set[str] = field(default_factory=set)


@dataclass
class PackerInfo:
    """Structured packer identification result."""
    packer_name: str
    confidence: str        # HIGH | MEDIUM | LOW
    mitre_ref: str
    detection_signals: list[str] = field(default_factory=list)


@dataclass
class DotNetReport:
    """Result from .NET obfuscator detection (ConfuserEx, NetReactor, etc.)"""
    is_dotnet: bool
    clr_version: str
    obfuscators_found: list[str] = field(default_factory=list)
    detection_signals: list[str] = field(default_factory=list)
    confidence: str = "NONE"   # HIGH | MEDIUM | LOW | NONE


@dataclass
class DetectionReport:
    file_path: str
    file_size: int
    file_entropy: float
    printable_string_count: int
    section_reports: list[SectionReport]
    import_report: ImportReport
    signature_hit: Optional[str]
    signals: list[Signal]
    score: int
    risk_level: RiskLevel
    packer_matches: list[PackerInfo] = field(default_factory=list)
    dotnet_report: Optional[DotNetReport] = None
