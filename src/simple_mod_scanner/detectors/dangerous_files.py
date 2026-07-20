from __future__ import annotations

from simple_mod_scanner.models import Finding, Severity
from simple_mod_scanner.zip_reader import ZipMember, read_bytes

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".cpl",
    ".msc",
    ".reg",
    ".lnk",
    ".url",
    ".iso",
    ".img",
    ".jar",
    ".pif",
}

# Extensions that are dangerous unless under a known safe tree.
CONDITIONAL_EXTENSIONS = {
    ".js": "ui/",  # BeamNG UI mods legitimately use JavaScript under ui/
}


def _normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _basename(path: str) -> str:
    return _normalize(path).rstrip("/").rsplit("/", 1)[-1]


def _extension(name: str) -> str:
    lower = name.lower()
    if "." not in lower:
        return ""
    return "." + lower.rsplit(".", 1)[-1]


def _js_allowed(path: str) -> bool:
    """Allow JS in ui/ or under vehicle gauge/screen UI folders.

    Location allowlisting only skips the 'unexpected .js path' rule.
    File contents are still fully scanned for malware patterns.
    """
    parts = path.lower().replace("\\", "/").split("/")
    if any(p == "ui" for p in parts[:-1]):
        return True
    # vehicles/<vehicle>/.../<folder with gauge|screen>/file.js
    if len(parts) >= 3 and parts[0] == "vehicles":
        for part in parts[2:-1]:  # skip vehicles/ and vehicle name; skip filename
            if "gauge" in part or "screen" in part:
                return True
        # also allow vehicles/<vehicle>/gauges_screen.js style (rare)
        filename = parts[-1]
        if "gauge" in filename or "screen" in filename:
            return True
    return False


def _has_double_extension(name: str) -> bool:
    lower = name.lower()
    parts = lower.split(".")
    if len(parts) < 3:
        return False
    # e.g. texture.png.exe
    return f".{parts[-1]}" in DANGEROUS_EXTENSIONS and parts[-2] in {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "dds",
        "jbeam",
        "pc",
        "lua",
        "txt",
        "json",
        "zip",
        "html",
    }


def scan_dangerous_files(members: list[ZipMember], zf) -> list[Finding]:
    findings: list[Finding] = []

    for member in members:
        if member.is_dir:
            continue

        path = _normalize(member.name)
        name = _basename(path)
        ext = _extension(name)
        lower_path = path.lower()

        if _has_double_extension(name):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="dangerous.double_extension",
                    path=path,
                    detail=f"Double extension disguising executable: {name}",
                )
            )
            continue

        if ext in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="dangerous.extension",
                    path=path,
                    detail=f"Dangerous file type ({ext}) inside mod archive",
                )
            )
            continue

        if ext in CONDITIONAL_EXTENSIONS and not _js_allowed(lower_path):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    rule_id="dangerous.js_outside_ui",
                    path=path,
                    detail="JavaScript outside ui/ and vehicle gauge/screen folders (contents still scanned when allowed)",
                )
            )

        # PE magic check for unexpected binaries
        if member.size >= 2 and ext not in {".dll", ".exe"}:
            try:
                header = read_bytes(zf, member.name, max_bytes=2)
            except Exception:
                continue
            if header[:2] == b"MZ":
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        rule_id="dangerous.pe_magic",
                        path=path,
                        detail="File starts with Windows PE magic (MZ) but is not named as an executable/DLL",
                    )
                )

    return findings
