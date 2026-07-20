from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from simple_mod_scanner.detectors.dangerous_files import scan_dangerous_files
from simple_mod_scanner.detectors.script_patterns import scan_script_patterns
from simple_mod_scanner.detectors.structure import scan_structure
from simple_mod_scanner.models import ScanResult, Severity
from simple_mod_scanner.zip_reader import ZipReadError, list_members, open_mod_zip

ProgressCallback = Callable[[int, int, str], None]


def discover_zips(path: Path) -> list[Path]:
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    if path.is_file():
        if path.suffix.lower() != ".zip":
            raise ValueError(f"Not a .zip file: {path}")
        return [path]
    zips = sorted(p for p in path.rglob("*.zip") if p.is_file())
    return zips


def scan_zip(path: Path) -> ScanResult:
    path = path.expanduser().resolve()
    result = ScanResult(zip_path=path)
    try:
        with open_mod_zip(path) as zf:
            members = list_members(zf)
            result.member_count = sum(1 for m in members if not m.is_dir)
            findings = []
            findings.extend(scan_structure(members))
            findings.extend(scan_dangerous_files(members, zf))
            findings.extend(scan_script_patterns(members, zf))
            findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.path, f.line or 0))
            result.findings = findings
    except ZipReadError as exc:
        result.error = str(exc)
    except OSError as exc:
        result.error = f"I/O error: {exc}"
    return result


def scan_path(path: Path, progress: ProgressCallback | None = None) -> list[ScanResult]:
    zips = discover_zips(path)
    results: list[ScanResult] = []
    total = len(zips)
    if total == 0:
        return results
    for index, zip_path in enumerate(zips, start=1):
        if progress:
            progress(index, total, zip_path.name)
        results.append(scan_zip(zip_path))
    return results


def summarize(results: Iterable[ScanResult]) -> dict[str, int]:
    counts = {"total": 0, "CLEAN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "ERROR": 0}
    for result in results:
        counts["total"] += 1
        counts[result.verdict.value] += 1
    return counts


def results_to_jsonable(results: list[ScanResult]) -> dict:
    return {
        "summary": summarize(results),
        "results": [r.to_dict() for r in results],
    }


def max_severity(result: ScanResult) -> Severity | None:
    if not result.findings:
        return None
    return max(result.findings, key=lambda f: f.severity.rank).severity
