from __future__ import annotations

from simple_mod_scanner.models import Finding, Severity
from simple_mod_scanner.zip_reader import ZipMember

VALID_TOP_LEVEL = frozenset(
    {
        "vehicles",
        "levels",
        "art",
        "assets",
        "lua",
        "scripts",
        "ui",
        "gameplay",
        "settings",
        "trackEditor",
        "vehicleGroups",
    }
)


def _normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _top_segments(members: list[ZipMember]) -> tuple[set[str], set[str]]:
    """Return (top-level dirs, top-level files)."""
    dirs: set[str] = set()
    files: set[str] = set()
    for member in members:
        path = _normalize(member.name).rstrip("/")
        if not path:
            continue
        parts = path.split("/")
        if len(parts) == 1:
            if member.is_dir or member.name.endswith("/"):
                dirs.add(parts[0])
            else:
                files.add(parts[0])
        else:
            dirs.add(parts[0])
    return dirs, files


def scan_structure(members: list[ZipMember]) -> list[Finding]:
    findings: list[Finding] = []

    if not members:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                rule_id="structure.empty",
                path="",
                detail="ZIP archive has no members",
            )
        )
        return findings

    for member in members:
        path = _normalize(member.name)
        if ".." in path.split("/"):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="structure.path_traversal",
                    path=path,
                    detail="Path contains '..' (zip slip / path traversal)",
                )
            )
        if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    rule_id="structure.absolute_path",
                    path=path,
                    detail="Archive member uses an absolute path",
                )
            )

    top_dirs, top_files = _top_segments(members)

    # Orphan files at ZIP root
    for name in sorted(top_files):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                rule_id="structure.orphan_root_file",
                path=name,
                detail="File at ZIP root outside a BeamNG top-level folder",
            )
        )

    unknown = {d for d in top_dirs if d not in VALID_TOP_LEVEL}
    valid_present = {d for d in top_dirs if d in VALID_TOP_LEVEL}

    # Classic wrapped packing: MyMod/vehicles/...
    if not valid_present and len(unknown) == 1:
        wrapper = next(iter(unknown))
        nested_valid = False
        for member in members:
            parts = _normalize(member.name).split("/")
            if len(parts) >= 2 and parts[0] == wrapper and parts[1] in VALID_TOP_LEVEL:
                nested_valid = True
                break
        if nested_valid:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule_id="structure.wrapped_mod",
                    path=wrapper + "/",
                    detail=(
                        f"Mod appears wrapped in '{wrapper}/' instead of BeamNG top-level "
                        "folders (vehicles/, lua/, …) at the ZIP root"
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    rule_id="structure.unknown_top_level",
                    path=wrapper + "/",
                    detail=f"Unknown top-level folder '{wrapper}' (not a standard BeamNG mod root)",
                )
            )
    else:
        for name in sorted(unknown):
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    rule_id="structure.unknown_top_level",
                    path=name + "/",
                    detail=f"Unknown top-level folder '{name}' mixed into the archive",
                )
            )

    if not valid_present and not any(f.rule_id == "structure.wrapped_mod" for f in findings):
        # No recognized layout at all
        if top_dirs or top_files:
            if not any(f.rule_id.startswith("structure.") for f in findings if f.rule_id != "structure.orphan_root_file"):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        rule_id="structure.no_valid_roots",
                        path="",
                        detail="No standard BeamNG top-level folders found at ZIP root",
                    )
                )

    return findings
