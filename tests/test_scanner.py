from __future__ import annotations

from pathlib import Path

import pytest

from simple_mod_scanner.detectors.script_patterns import RULES
from simple_mod_scanner.models import Verdict
from simple_mod_scanner.scanner import discover_zips, scan_path, scan_zip

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


def test_eval_identifier_lookup_is_low_only() -> None:
    result = scan_zip(FIX / "clean_gauges_screen.zip")
    eval_findings = [f for f in result.findings if f.rule_id == "script.js_eval"]
    assert eval_findings
    assert all(f.severity.value == "low" for f in eval_findings)


def test_string_eval_in_gauge_folder_still_high() -> None:
    result = scan_zip(FIX / "gauge_hidden_eval.zip")
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    eval_findings = [f for f in result.findings if f.rule_id == "script.js_eval"]
    assert any(f.severity.value == "high" for f in eval_findings)


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


def test_extensions_load_false_positive_is_clean() -> None:
    result = scan_zip(FIX / "fp_extensions_load.zip")
    assert result.verdict == Verdict.CLEAN
    assert not any(f.rule_id == "script.loadstring" for f in result.findings)


def test_evil_os_execute() -> None:
    result = scan_zip(FIX / "evil_os_execute.zip")
    assert result.verdict == Verdict.MALICIOUS
    assert any(f.rule_id == "script.os_execute" for f in result.findings)


def test_evil_ffi() -> None:
    result = scan_zip(FIX / "evil_ffi.zip")
    assert result.verdict == Verdict.MALICIOUS
    assert any(f.rule_id.startswith("script.ffi") for f in result.findings)


def test_evil_websocket() -> None:
    result = scan_zip(FIX / "evil_websocket.zip")
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    assert any(f.rule_id == "script.websocket" for f in result.findings)


def test_evil_write_appdata() -> None:
    result = scan_zip(FIX / "evil_write_appdata.zip")
    assert result.verdict in {Verdict.SUSPICIOUS, Verdict.MALICIOUS}
    assert any(f.rule_id in {"script.risky_file_write", "script.appdata"} for f in result.findings)


def test_obfuscated_lua_is_suspicious_not_critical_alone() -> None:
    result = scan_zip(FIX / "obfuscated_lua.zip")
    assert result.verdict == Verdict.SUSPICIOUS
    assert any(f.rule_id == "script.obfuscated_lua" for f in result.findings)
    assert not any(f.severity.value == "critical" for f in result.findings)


def test_html_credit_comment_is_clean() -> None:
    result = scan_zip(FIX / "html_credit_comment.zip")
    assert result.verdict == Verdict.CLEAN
    assert not any(f.severity.value in {"medium", "high", "critical"} for f in result.findings)


def test_discover_folder() -> None:
    zips = discover_zips(FIX)
    assert len(zips) >= 5
    results = scan_path(FIX)
    assert len(results) == len(zips)
