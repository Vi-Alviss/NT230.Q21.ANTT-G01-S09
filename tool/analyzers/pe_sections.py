from __future__ import annotations

from models import SectionReport


SUSPICIOUS_SECTION_NAMES = {
    ".upx0",
    ".upx1",
    "upx0",
    "upx1",
    ".aspack",
    ".adata",
    ".packed",
    ".petite",
}


def _clean_section_name(raw_name: bytes) -> str:
    return raw_name.decode("utf-8", errors="ignore").rstrip("\x00").strip()


def analyze_sections(pe, section_entropies: list[float]) -> list[SectionReport]:
    """Analyze section-level anomalies and return structured reports."""
    reports: list[SectionReport] = []

    for idx, section in enumerate(pe.sections):
        section_name = _clean_section_name(section.Name)
        entropy = section_entropies[idx] if idx < len(section_entropies) else 0.0

        reasons: list[str] = []
        if entropy > 7.2:
            reasons.append("high section entropy (>7.2)")

        size_of_raw_data = int(section.SizeOfRawData)
        virtual_size = int(section.Misc_VirtualSize)
        if size_of_raw_data == 0 and virtual_size > 0:
            reasons.append("raw size is zero but virtual size > 0")

        if section_name.lower() in SUSPICIOUS_SECTION_NAMES:
            reasons.append("suspicious section name")

        reports.append(
            SectionReport(
                index=idx,
                name=section_name,
                entropy=entropy,
                size_of_raw_data=size_of_raw_data,
                virtual_size=virtual_size,
                suspicious_reasons=reasons,
            )
        )

    return reports
