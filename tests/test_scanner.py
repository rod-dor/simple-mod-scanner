from __future__ import annotations

from pathlib import Path

import pytest

from beamng_mod_scanner.detectors.script_patterns import RULES
from beamng_mod_scanner.models import Verdict
from beamng_mod_scanner.scanner import discover_zips, scan_path, scan_zip

FIX = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def ensure_fixtures() -> None:
    from tests.generate_fixtures import main

    main()


def test_clean_vehicle_is_clean() -> None:
    result = scan_zip(FIX / "clean_vehicle.zip")
    assert result.error is None
    assert result.verdict == Verdict.CLEAN
    assert result.member_count >= 2


def test_wrapped_mod_is_suspicious() -> None:
    result = scan_zip(FIX / "wrapped_mod.zip")
    assert result.verdict == Verdict.SUSPICIOUS
    assert any(f.rule_id == "structure.wrapped_mod" for f in result.findings)


def test_exe_is_malicious() -> None:
    result = scan_zip(FIX / "with_exe.zip")
    assert result.verdict == Verdict.MALICIOUS
    assert any(f.rule_id == "dangerous.extension" for f in result.findings)


def test_malicious_lua() -> None:
    result = scan_zip(FIX / "malicious_lua.zip")
    assert result.verdict == Verdict.MALICIOUS
    rule_ids = {f.rule_id for f in result.findings}
    assert "script.os_execute" in rule_ids or "script.ffi_require" in rule_ids
    assert any(f.line for f in result.findings)


def test_js_outside_ui() -> None:
    result = scan_zip(FIX / "suspicious_js.zip")
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    assert any(
        f.rule_id in {"dangerous.js_outside_ui", "script.js_eval"} for f in result.findings
    )


def test_clean_gauges_screen_is_clean() -> None:
    result = scan_zip(FIX / "clean_gauges_screen.zip")
    assert result.error is None
    assert result.verdict == Verdict.CLEAN
    assert not any(f.severity.value in {"medium", "high", "critical"} for f in result.findings)


def test_js_eval_rule_ignores_lowercase_function() -> None:
    rule = next(r for r in RULES if r.rule_id == "script.js_eval")
    assert rule.pattern.search("function () {") is None
    assert rule.pattern.search(".directive('x', function () {") is None
    assert rule.pattern.search("eval('x')") is not None
    assert rule.pattern.search("Function('return 1')") is not None


def test_remote_js_malware_is_caught() -> None:
    result = scan_zip(FIX / "remote_js_malware.zip")
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    rule_ids = {f.rule_id for f in result.findings}
    assert "script.remote_script_src" in rule_ids or "script.http_client_with_url" in rule_ids
    assert "script.atob_decode" in rule_ids


def test_discover_folder() -> None:
    zips = discover_zips(FIX)
    assert len(zips) >= 5
    results = scan_path(FIX)
    assert len(results) == len(zips)
