from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PackerMatch:
    """Detailed packer detection result."""
    packer_name: str
    match_reason: str
    confidence: str  # "HIGH" | "MEDIUM" | "LOW"
    mitre_ref: str = ""
    signals: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Byte-level magic signatures
# ---------------------------------------------------------------------------
BYTE_SIGNATURES: list[tuple[bytes, str, str]] = [
    # ── UPX ──────────────────────────────────────────────────────────────────
    (b"UPX!",              "UPX",                  "HIGH"),
    (b"UPX0",              "UPX",                  "HIGH"),
    (b"UPX1",              "UPX",                  "HIGH"),

    # ── MPRESS ───────────────────────────────────────────────────────────────
    (b"MPRESS1",           "MPRESS",               "HIGH"),
    (b"MPRESS2",           "MPRESS",               "HIGH"),

    # ── The Enigma Protector ─────────────────────────────────────────────────
    (b"Enigma protector",  "The Enigma Protector",  "HIGH"),
    (b"enigma_pro",        "The Enigma Protector",  "HIGH"),
    (b".enigma1",          "The Enigma Protector",  "HIGH"),
    (b".enigma2",          "The Enigma Protector",  "HIGH"),

    # ── Themida / WinLicense ─────────────────────────────────────────────────
    (b".themida",          "Themida",               "HIGH"),
    (b"Themida",           "Themida",               "HIGH"),
    (b"WinLicense",        "Themida",               "HIGH"),
    (b"__TLS_Used",        "Themida",               "MEDIUM"),

    # ── VMProtect ────────────────────────────────────────────────────────────
    (b".vmp0",             "VMProtect",             "HIGH"),
    (b".vmp1",             "VMProtect",             "HIGH"),
    (b"VMProtect",         "VMProtect",             "HIGH"),
    (b"vmp_begin",         "VMProtect",             "HIGH"),
    (b"vmp_end",           "VMProtect",             "HIGH"),

    # ── Obsidium ─────────────────────────────────────────────────────────────
    (b".obsidium",         "Obsidium",              "HIGH"),
    (b"Obsidium",          "Obsidium",              "HIGH"),

    # ── PECompact ────────────────────────────────────────────────────────────
    (b"PECompact2",        "PECompact",             "HIGH"),
    (b"PEC2",              "PECompact",             "MEDIUM"),

    # ── ASPack ───────────────────────────────────────────────────────────────
    (b"ASPack",            "ASPack",                "HIGH"),
    (b".aspack",           "ASPack",                "HIGH"),
    (b".adata",            "ASPack",                "MEDIUM"),

    # ── FSG ──────────────────────────────────────────────────────────────────
    (b"FSG!",              "FSG",                   "HIGH"),
    (b"\xeb\x02\xcd\x20",  "FSG",                   "MEDIUM"),

    # ── PESpin ───────────────────────────────────────────────────────────────
    (b"PESpin",            "PESpin",                "HIGH"),
    (b".spin",             "PESpin",                "HIGH"),

    # ── Morphine ─────────────────────────────────────────────────────────────
    (b"Morphine",          "Morphine",              "HIGH"),

    # ── ExeStealth ───────────────────────────────────────────────────────────
    (b"ExeStealth",        "ExeStealth",            "HIGH"),
    (b"W32.Exe-Stealth",   "ExeStealth",            "HIGH"),

    # ── Andromeda (Gamarue) ───────────────────────────────────────────────────
    (b"Andromeda",         "Andromeda",             "HIGH"),
    (b"gamarue",           "Andromeda",             "HIGH"),

    # ── Exe Packer 2.300 ─────────────────────────────────────────────────────
    (b"Exe Packer",        "Exe Packer 2.300",      "HIGH"),
    (b"ExePack",           "Exe Packer 2.300",      "MEDIUM"),

    # ── ConfuserEx (.NET obfuscator) ─────────────────────────────────────────
    # Confidence MEDIUM ở đây — HIGH chỉ khi dotnet.py xác nhận CLR header
    (b"ConfuserEx",        "ConfuserEx",            "MEDIUM"),
    (b"ConfusedBy",        "ConfuserEx",            "MEDIUM"),
    (b"Confuser.Core",     "ConfuserEx",            "MEDIUM"),
    (b"__ConfuserEx__",    "ConfuserEx",            "HIGH"),   # resource marker đặc trưng

    # ── NetReactor (.NET obfuscator / packer by Eziriz) ──────────────────────
    (b"NET_Reactor",       "NetReactor",            "HIGH"),
    (b"Eziriz",            "NetReactor",            "HIGH"),
    (b"NR_ANTITAMPER",     "NetReactor",            "HIGH"),
    (b"NR_LICENSE",        "NetReactor",            "HIGH"),
    (b"NetReactor",        "NetReactor",            "MEDIUM"),
]


# ---------------------------------------------------------------------------
# 2. PE section-name → packer mapping
# ---------------------------------------------------------------------------
SUSPICIOUS_SECTION_NAMES: dict[str, str] = {
    ".upx0":      "UPX",
    ".upx1":      "UPX",
    "upx0":       "UPX",
    "upx1":       "UPX",
    ".enigma1":   "The Enigma Protector",
    ".enigma2":   "The Enigma Protector",
    ".themida":   "Themida",
    ".winlicen":  "Themida",
    ".vmp0":      "VMProtect",
    ".vmp1":      "VMProtect",
    ".vmp2":      "VMProtect",
    ".obsidium":  "Obsidium",
    ".aspack":    "ASPack",
    ".adata":     "ASPack",
    ".spin":      "PESpin",
    ".petite":    "Petite",
    ".mpress":    "MPRESS",
    ".packed":    "Generic packer",
}


# ---------------------------------------------------------------------------
# 3. MITRE ATT&CK reference per packer family
# ---------------------------------------------------------------------------
PACKER_MITRE: dict[str, str] = {
    "UPX":                   "T1027.002 — Software Packing",
    "MPRESS":                "T1027.002 — Software Packing",
    "The Enigma Protector":  "T1027.002 / T1055 — Process Injection",
    "Themida":               "T1027.002 / T1055.012 — Process Hollowing",
    "VMProtect":             "T1027.009 — Embedded Payloads / T1027.002",
    "Obsidium":              "T1027.002 — Software Packing",
    "PECompact":             "T1027.002 — Software Packing",
    "ASPack":                "T1027.002 — Software Packing",
    "FSG":                   "T1027.002 — Software Packing",
    "PESpin":                "T1027.002 / T1027.005 — Indicator Removal",
    "Morphine":              "T1027.002 — Software Packing",
    "ExeStealth":            "T1027.002 / T1036 — Masquerading",
    "Andromeda":             "T1027.002 / T1055 — Process Injection",
    "Exe Packer 2.300":      "T1027.002 — Software Packing",
    "Generic packer":        "T1027 — Obfuscated Files or Information",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_packer_signature(data: bytes) -> Optional[str]:
    """Legacy compat: return first matched packer name string, or None."""
    result = detect_packer_signatures(data)
    if result:
        return result[0].packer_name
    return None


def detect_packer_signatures(data: bytes) -> list[PackerMatch]:
    """
    Full multi-match detection.
    Returns deduplicated list of PackerMatch ordered by confidence (HIGH first).
    """
    if not data:
        return []

    found: dict[str, PackerMatch] = {}

    def _add(packer: str, reason: str, confidence: str) -> None:
        if packer not in found:
            found[packer] = PackerMatch(
                packer_name=packer,
                match_reason=reason,
                confidence=confidence,
                mitre_ref=PACKER_MITRE.get(packer, "T1027 — Obfuscated Files or Information"),
                signals=[reason],
            )
        else:
            existing = found[packer]
            if confidence == "HIGH" and existing.confidence != "HIGH":
                existing.confidence = "HIGH"
            existing.signals.append(reason)
            existing.match_reason = f"{len(existing.signals)} markers found"

    def _search(pattern: bytes, data: bytes) -> str | None:
        """
        Search pattern in raw bytes and UTF-16LE.
        Rules to minimize false positives:
        - Raw bytes: always search (exact match)
        - UTF-16LE: only for patterns >= 5 bytes (shorter ones match too many substrings)
        - Case-insensitive: DISABLED — causes false positives for short/common patterns
        """
        if pattern in data:
            return "raw"
        # UTF-16LE only for patterns long enough to be distinctive
        if len(pattern) >= 5:
            try:
                utf16 = pattern.decode("ascii").encode("utf-16-le")
                if utf16 in data:
                    return "utf16le"
            except (UnicodeDecodeError, AttributeError):
                pass
        return None

    for pattern, packer_name, confidence in BYTE_SIGNATURES:
        encoding = _search(pattern, data)
        if encoding:
            suffix = f" [{encoding}]" if encoding != "raw" else ""
            _add(packer_name, f"Byte marker: {pattern!r}{suffix}", confidence)

    # UPX double-marker bonus
    if b"UPX0" in data and b"UPX1" in data:
        _add("UPX", "Both UPX0+UPX1 section markers present", "HIGH")

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(found.values(), key=lambda m: order.get(m.confidence, 3))


def check_section_names_for_packers(section_names: list[str]) -> list[PackerMatch]:
    """Return PackerMatch for any known-packer PE section names."""
    found: dict[str, PackerMatch] = {}
    for raw_name in section_names:
        lower = raw_name.lower().strip()
        if lower in SUSPICIOUS_SECTION_NAMES:
            packer = SUSPICIOUS_SECTION_NAMES[lower]
            if packer not in found:
                found[packer] = PackerMatch(
                    packer_name=packer,
                    match_reason=f"PE section name: {raw_name!r}",
                    confidence="HIGH",
                    mitre_ref=PACKER_MITRE.get(packer, "T1027"),
                    signals=[f"Section: {raw_name}"],
                )
            else:
                found[packer].signals.append(f"Section: {raw_name}")
    return list(found.values())


# ---------------------------------------------------------------------------
# .NET obfuscator entries (used for MITRE ref lookup from dotnet.py results)
# ---------------------------------------------------------------------------
PACKER_MITRE["ConfuserEx"]  = "T1027.002 — Software Packing / T1027.010 — Command Obfuscation (.NET)"
PACKER_MITRE["NetReactor"]  = "T1027.002 — Software Packing / T1140 — Deobfuscate/Decode at Runtime"
