from __future__ import annotations

"""
analyzers/dotnet.py — .NET assembly obfuscator/packer detection
Targets: ConfuserEx, .NET Reactor (NetReactor)

Detection strategy:
  1. Confirm file is a .NET assembly (CLR header present via pefile)
  2. Scan raw bytes for known string markers (module-level attributes, resource names)
  3. Check for characteristic section/resource patterns
  4. Heuristic: abnormal metadata stream names (ConfuserEx renames streams)
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DotNetReport:
    is_dotnet: bool
    clr_version: str                       # e.g. "v4.0.30319" or ""
    obfuscators_found: list[str] = field(default_factory=list)
    detection_signals: list[str] = field(default_factory=list)
    confidence: str = "NONE"               # HIGH | MEDIUM | LOW | NONE


# ---------------------------------------------------------------------------
# Byte-level markers embedded by each tool
# ---------------------------------------------------------------------------

# ConfuserEx writes a custom attribute into the assembly:
#   [assembly: ConfusedByAttribute("ConfuserEx ...")]
# Also renames the #Strings metadata stream header (sometimes to garbage bytes)
# and may embed a "__ConfuserEx__" resource.
CONFUSEREX_MARKERS: list[tuple[bytes, str]] = [
    (b"ConfuserEx",            "ConfuserEx attribute string found"),
    (b"Confuser.Core",         "Confuser.Core namespace reference found"),
    (b"ConfusedBy",            "ConfusedByAttribute marker found"),
    (b"__ConfuserEx__",        "ConfuserEx embedded resource marker"),
    (b"confuserex",            "ConfuserEx lowercase marker"),
    # Older Confuser (non-Ex)
    (b"Confuser 1.",           "Confuser v1.x marker found"),
    (b"Confused by",           "Confuser attribute string found"),
]

# .NET Reactor embeds licensing/protection strings and a known native stub.
# Key markers observed in protected assemblies:
NETREACTOR_MARKERS: list[tuple[bytes, str]] = [
    (b"NET_Reactor",           ".NET Reactor product string found"),
    (b"NetReactor",            ".NET Reactor name string found"),
    (b"Eziriz",                "Eziriz (NetReactor vendor) string found"),
    (b".NETReactor",           ".NET Reactor marker found"),
    (b"net_reactor",           ".NET Reactor lowercase marker found"),
    # NetReactor injects a native x86 stub section sometimes labelled:
    (b"NR_ANTITAMPER",         ".NET Reactor anti-tamper marker found"),
    (b"NR_LICENSE",            ".NET Reactor license marker found"),
    # Characteristic string in NetReactor-protected WinForms stubs
    (b"Reactor.Properties",    ".NET Reactor properties namespace found"),
]

# ---------------------------------------------------------------------------
# NetReactor structural fingerprint (v6.x+, no string markers)
# Observed characteristics:
#   - .NET assembly (BSJB present)
#   - Import: ONLY mscoree.dll with _CorExeMain or _CorDllMain
#   - Metadata streams (#~ / #-) absent or encrypted → not found in raw bytes
#   - High entropy in .text section (encrypted IL bytecode)
#   - Native x86 stub prepended before CLR header
# ---------------------------------------------------------------------------
NETREACTOR_ONLY_IMPORTS = {"_corexemain", "_cordllmain"}
MSCOREE = b"mscoree.dll"

# CLR header magic — confirms file is a .NET assembly
# IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR / MSIL magic bytes in metadata
DOTNET_MAGIC_MARKERS: list[bytes] = [
    b"BSJB",          # CLI metadata signature (every .NET assembly has this)
    b"#~",            # Compressed metadata stream header
    b"#Strings",      # Metadata string heap name
    b"#Blob",         # Blob heap
    b"#GUID",         # GUID heap
    b"#US",           # User string heap
]

# ConfuserEx sometimes renames #Strings → random garbage — absence of normal
# stream names combined with BSJB present is itself a signal.
NORMAL_STREAM_NAMES = {b"#~", b"#-", b"#Strings", b"#Blob", b"#GUID", b"#US"}


# ---------------------------------------------------------------------------
# Structural heuristics (for obfuscators that strip string markers)
# ---------------------------------------------------------------------------

def _detect_netreactor_structure(pe, data: bytes, file_size: int,
                                  section_entropies: list[float],
                                  import_count: int,
                                  has_confuserex_markers: bool = False) -> list[str]:
    """
    NetReactor structural fingerprint (no string markers needed).

    Discriminators vs ConfuserEx:
      - NetReactor prepends a *native x86 stub* → BSJB offset is typically
        0x400..0x3000 (small fixed stub). ConfuserEx does NOT prepend a stub;
        its BSJB sits near offset 0 or inside the normal PE .text section.
      - NetReactor's stub size is characteristic: usually 0x200–0x6000 bytes.
      - ConfuserEx keeps the #Strings / #Blob heap names intact (only renames
        #~ → junk), whereas NetReactor encrypts the entire metadata → ALL
        stream names gone.

    Requires ALL of the following to fire:
      1. BSJB in data
      2. has_confuserex_markers is False  (bail out early if ConfuserEx confirmed)
      3. Import table: ONLY mscoree.dll + _CorExeMain/_CorDllMain
      4. BSJB offset is in the NetReactor stub range (0x200 < offset < 0x8000)
      5. ALL of #~, #-, #Strings, #Blob, #GUID absent from raw bytes
    """
    signals: list[str] = []

    if b"BSJB" not in data:
        return signals

    # Hard-bail: if ConfuserEx string markers are already confirmed, do not
    # add a contradictory NetReactor structural hit.
    if has_confuserex_markers:
        return signals

    # ── Discriminator 1: BSJB must be in the native-stub range ──────────────
    # NetReactor prepends a small native stub (typically 0x200–0x6000 bytes).
    # ConfuserEx does not; its BSJB is either at offset 0 or deep inside .text
    # (often > 0x10000).
    bsjb_idx = data.find(b"BSJB")
    NR_STUB_MIN = 0x200
    NR_STUB_MAX = 0x8000
    if not (NR_STUB_MIN < bsjb_idx < NR_STUB_MAX):
        return signals   # offset outside expected NetReactor stub range

    signals.append(
        f"BSJB metadata at offset {bsjb_idx:#x} — consistent with NetReactor native stub range"
    )

    # ── Discriminator 2: import table is ONLY mscoree.dll + _CorExeMain ─────
    try:
        import_entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        dll_names = [
            e.dll.lower().decode("ascii", errors="ignore")
            for e in import_entries if e.dll
        ]
        all_funcs: set[str] = set()
        for e in import_entries:
            for imp in e.imports:
                if imp.name:
                    all_funcs.add(imp.name.lower().decode("ascii", errors="ignore"))

        if (dll_names
                and all(d == "mscoree.dll" for d in dll_names)
                and all_funcs
                and all_funcs <= NETREACTOR_ONLY_IMPORTS):
            signals.append(
                "Import table: only mscoree.dll + _CorExeMain — NetReactor native stub pattern"
            )
        else:
            # If import table doesn't match exactly, not confident enough
            return []
    except Exception:
        return []

    # ── Discriminator 3: ALL standard metadata stream names absent ───────────
    # NetReactor encrypts the entire metadata blob; ConfuserEx leaves #Strings
    # and #Blob visible (only renames #~ to junk).
    all_streams = [b"#~", b"#-", b"#Strings", b"#Blob", b"#GUID"]
    found_streams = [s for s in all_streams if s in data]
    if len(found_streams) == 0:
        signals.append(
            "All .NET metadata stream names absent — entire metadata encrypted (NetReactor pattern)"
        )
    else:
        # At least one stream name visible → more likely ConfuserEx, not NetReactor
        return []

    # All 3 discriminators passed
    return signals


def _detect_confuserex_structure(pe, data: bytes,
                                  section_entropies: list[float],
                                  import_count: int) -> list[str]:
    """
    ConfuserEx structural fallback when string markers are absent:
    - CLR present
    - All sections high entropy (> 7.0)
    - Import count very low
    - #Strings stream renamed/absent
    """
    signals: list[str] = []

    if b"BSJB" not in data:
        return signals

    if import_count <= 2:
        signals.append("Import count <= 2")

    high_ent_sections = sum(1 for e in section_entropies if e > 7.0)
    if len(section_entropies) > 0 and high_ent_sections == len(section_entropies):
        signals.append(f"All {high_ent_sections} sections have entropy > 7.0")

    if b"#Strings" not in data and b"#~" not in data:
        signals.append("Both #Strings and #~ metadata streams absent")

    return signals if len(signals) >= 3 else []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_dotnet(pe, data: bytes,
                   section_entropies: list[float] | None = None,
                   import_count: int = 0) -> DotNetReport:
    """
    Detect .NET assembly and check for ConfuserEx / NetReactor markers.
    pe  : pefile.PE object (fast_load=True is fine)
    data: raw bytes of the file
    """
    # ── Step 1: confirm .NET (CLR directory entry present + BSJB magic) ──────
    is_dotnet = False
    clr_version = ""

    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        if clr_dir.VirtualAddress != 0 and clr_dir.Size != 0:
            is_dotnet = True
    except (AttributeError, IndexError):
        pass

    if not is_dotnet and b"BSJB" not in data:
        return DotNetReport(is_dotnet=False, clr_version="")

    is_dotnet = True  # BSJB alone is sufficient confirmation

    # Try to extract CLR runtime version string (appears after BSJB)
    bsjb_idx = data.find(b"BSJB")
    if bsjb_idx != -1 and bsjb_idx + 20 < len(data):
        # version string is at offset +12 from BSJB, null-terminated, max 256 bytes
        ver_start = bsjb_idx + 12
        ver_end   = data.find(b"\x00", ver_start)
        if ver_end != -1 and ver_end - ver_start < 32:
            try:
                clr_version = data[ver_start:ver_end].decode("ascii", errors="ignore").strip()
            except Exception:
                clr_version = ""

    signals:      list[str] = []
    obfuscators:  list[str] = []
    confidence_levels: dict[str, int] = {}  # obfuscator → hit count

    # ── Step 2: scan for ConfuserEx markers ──────────────────────────────────
    def _match(pattern: bytes, data: bytes) -> bool:
        """
        Match in raw bytes and UTF-16LE (>= 5 bytes only).
        Case-insensitive disabled to avoid false positives.
        """
        if pattern in data:
            return True
        if len(pattern) >= 5:
            try:
                utf16 = pattern.decode("ascii").encode("utf-16-le")
                if utf16 in data:
                    return True
            except (UnicodeDecodeError, AttributeError):
                pass
        return False

    confuser_hits = 0
    for pattern, reason in CONFUSEREX_MARKERS:
        if _match(pattern, data):
            signals.append(f"[ConfuserEx] {reason}")
            confuser_hits += 1

    if confuser_hits > 0:
        obfuscators.append("ConfuserEx")
        confidence_levels["ConfuserEx"] = confuser_hits

    # ── Step 3: scan for .NET Reactor markers ────────────────────────────────
    reactor_hits = 0
    for pattern, reason in NETREACTOR_MARKERS:
        if _match(pattern, data):
            signals.append(f"[NetReactor] {reason}")
            reactor_hits += 1

    if reactor_hits > 0:
        obfuscators.append("NetReactor")
        confidence_levels["NetReactor"] = reactor_hits

    # ── Step 3b: NetReactor structural fingerprint ───────────────────────────
    # NetReactor v6+ không embed string marker — detect qua PE import + metadata
    def _detect_netreactor_structural(pe, data: bytes,
                                      has_confuserex: bool) -> tuple[bool, list[str]]:
        nr_signals: list[str] = []

        # Hard-bail: ConfuserEx markers already confirmed — don't add NetReactor
        if has_confuserex:
            return False, []

        # Check 1: import table chỉ có mscoree.dll + _CorExeMain/_CorDllMain
        try:
            import_entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            dll_names = [
                e.dll.lower().decode("ascii", errors="ignore")
                for e in import_entries
                if e.dll
            ]
            if dll_names and all(d == b"mscoree.dll".decode() for d in dll_names):
                # Check function names
                all_funcs: set[str] = set()
                for e in import_entries:
                    for imp in e.imports:
                        if imp.name:
                            all_funcs.add(imp.name.lower().decode("ascii", errors="ignore"))
                if all_funcs and all_funcs <= NETREACTOR_ONLY_IMPORTS:
                    nr_signals.append(
                        "Import table: only mscoree.dll + _CorExeMain — NetReactor native stub pattern"
                    )
        except Exception:
            pass

        # Check 2: metadata streams bị encrypt (#~ / #- absent mặc dù BSJB present)
        # Phân biệt với ConfuserEx: ConfuserEx chỉ rename #~ nhưng giữ #Strings/#Blob;
        # NetReactor encrypt toàn bộ → TẤT CẢ stream names đều absent.
        if b"BSJB" in data:
            all_stream_names = [b"#~", b"#-", b"#Strings", b"#Blob", b"#GUID"]
            found = [s for s in all_stream_names if s in data]
            if len(found) == 0:
                # Toàn bộ metadata stream names absent → NetReactor full encryption
                nr_signals.append(
                    "CLR metadata present (BSJB) but ALL stream names absent — full metadata encryption (NetReactor)"
                )
            elif not (b"#~" in data or b"#-" in data):
                # Chỉ compressed stream absent — có thể ConfuserEx
                # KHÔNG thêm signal này vì không đủ phân biệt
                pass

        # Check 3: native stub trước BSJB trong range đặc trưng của NetReactor
        # NetReactor stub thường 0x200–0x8000 bytes.
        # ConfuserEx không prepend stub → BSJB offset nằm trong .text section (thường > 0x10000)
        # hoặc gần đầu file (< 0x200).
        bsjb_idx = data.find(b"BSJB")
        NR_STUB_MIN = 0x200
        NR_STUB_MAX = 0x8000
        if NR_STUB_MIN < bsjb_idx < NR_STUB_MAX:
            nr_signals.append(
                f"BSJB metadata at offset {bsjb_idx:#x} — in NetReactor native stub range (0x200–0x8000)"
            )
        # KHÔNG emit signal nếu offset ngoài range này

        # Cần ít nhất 2 signal ĐỦ PHÂN BIỆT để kết luận NetReactor structural
        return len(nr_signals) >= 2, nr_signals

    if "NetReactor" not in confidence_levels:
        nr_hit, nr_sigs = _detect_netreactor_structural(pe, data,
                                                         has_confuserex=confuser_hits > 0)
        if nr_hit:
            for s in nr_sigs:
                signals.append(f"[NetReactor] {s}")
            obfuscators.append("NetReactor")
            confidence_levels["NetReactor"] = len(nr_sigs)
        elif nr_sigs:  # 1 signal — LOW confidence
            signals.append(f"[NetReactor?] {nr_sigs[0]}")

    # ── Step 4: stream name heuristic (ConfuserEx renames metadata streams) ──
    normal_streams_found = sum(1 for s in NORMAL_STREAM_NAMES if s in data)
    if is_dotnet and normal_streams_found == 0 and confuser_hits == 0:
        # All stream names wiped — strong ConfuserEx or similar
        signals.append("[ConfuserEx] All normal metadata stream names absent — possible stream renaming obfuscation")
        if "ConfuserEx" not in obfuscators:
            obfuscators.append("ConfuserEx")
        confidence_levels["ConfuserEx"] = confidence_levels.get("ConfuserEx", 0) + 2

    # ── Step 4b: structural fallback (markers stripped) ────────────────────────
    _ents = section_entropies or []
    if confuser_hits == 0:
        struct_signals = _detect_confuserex_structure(pe, data, _ents, import_count)
        if struct_signals:
            signals.extend(f"[ConfuserEx-struct] {s}" for s in struct_signals)
            if "ConfuserEx" not in obfuscators:
                obfuscators.append("ConfuserEx")
            confidence_levels["ConfuserEx"] = confidence_levels.get("ConfuserEx", 0) + len(struct_signals)

    # Chỉ chạy structural NetReactor fallback nếu:
    #   (a) không có string marker của NetReactor, VÀ
    #   (b) NetReactor chưa được thêm qua inline check ở Step 3b, VÀ
    #   (c) không có ConfuserEx markers (để tránh false-positive trên Confuser.exe)
    if reactor_hits == 0 and "NetReactor" not in confidence_levels and confuser_hits == 0:
        file_size = len(data)
        struct_signals = _detect_netreactor_structure(
            pe, data, file_size, _ents, import_count,
            has_confuserex_markers=confuser_hits > 0,
        )
        if struct_signals:
            signals.extend(f"[NetReactor-struct] {s}" for s in struct_signals)
            if "NetReactor" not in obfuscators:
                obfuscators.append("NetReactor")
            confidence_levels["NetReactor"] = confidence_levels.get("NetReactor", 0) + len(struct_signals)

    # ── Step 5: determine overall confidence ─────────────────────────────────
    if not confidence_levels:
        confidence = "NONE"
    else:
        max_hits = max(confidence_levels.values())
        if max_hits >= 2:
            confidence = "HIGH"
        elif max_hits == 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

    return DotNetReport(
        is_dotnet=is_dotnet,
        clr_version=clr_version,
        obfuscators_found=obfuscators,
        detection_signals=signals,
        confidence=confidence,
    )
