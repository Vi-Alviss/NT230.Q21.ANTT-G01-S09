from __future__ import annotations

from models import ImportReport


SUSPICIOUS_IMPORT_APIS = {
    # --- Injection / Memory ---
    "virtualalloc",
    "virtualprotect",
    "writeprocessmemory",
    "createremotethread",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "ntunmapviewofsection",
    # --- Crypto (BCrypt) — T1140 ---
    "bcryptdecrypt",
    "bcryptencrypt",
    "bcryptopenalgorithmprovider",
    "bcryptgeneratesymmetrickey",
    "bcryptdestroykey",
    # --- Drop-to-disk — T1027/T1036 ---
    "createfilea",
    "createfilew",
    "writefile",
    "getenvironmentvariablea",
    "getenvironmentvariablew",
    # --- Execution — T1106 ---
    "createprocessa",
    "createprocessw",
    "shellexecutea",
    "shellexecutew",
    "winexec",
}

# Nhóm để detect combo pattern
CRYPTO_APIS  = {"bcryptdecrypt", "bcryptencrypt", "cryptdecrypt", "cryptencrypt"}
EXEC_APIS    = {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "winexec"}
WRITE_APIS   = {"writefile", "createfilea", "createfilew"}


def analyze_imports(pe) -> ImportReport:
    """Analyze import table and return count + suspicious API list."""
    imported_names: list[str] = []

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imported_symbol in entry.imports:
            if imported_symbol.name:
                imported_names.append(imported_symbol.name.decode("utf-8", errors="ignore"))

    lowered = {name.lower() for name in imported_names}
    suspicious_apis = sorted(
        api_name for api_name in imported_names if api_name.lower() in SUSPICIOUS_IMPORT_APIS
    )

    unique_suspicious = sorted(set(suspicious_apis), key=str.lower)

    return ImportReport(
        total_imports=len(lowered),
        suspicious_apis=unique_suspicious,
        all_imports_lower=lowered,  # truyền xuống để detector dùng cho combo check
    )
