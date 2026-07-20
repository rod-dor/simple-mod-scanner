from __future__ import annotations

import re
from dataclasses import dataclass

from beamng_mod_scanner.models import Finding, Severity
from beamng_mod_scanner.zip_reader import ZipMember, read_text


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    detail: str
    languages: frozenset[str]


RULES: list[PatternRule] = [
    PatternRule(
        "script.os_execute",
        Severity.CRITICAL,
        re.compile(r"\bos\.execute\s*\(", re.IGNORECASE),
        "Calls os.execute (process execution)",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.io_popen",
        Severity.CRITICAL,
        re.compile(r"\bio\.popen\s*\(", re.IGNORECASE),
        "Calls io.popen (shell command)",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.loadstring",
        Severity.CRITICAL,
        re.compile(r"\b(?:loadstring|load)\s*\(", re.IGNORECASE),
        "Dynamic code loading (load/loadstring)",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.package_loadlib",
        Severity.CRITICAL,
        re.compile(r"\bpackage\.loadlib\s*\(", re.IGNORECASE),
        "Loads a native shared library via package.loadlib",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.shell_strings",
        Severity.CRITICAL,
        re.compile(r"(?:cmd\.exe|powershell(?:\.exe)?|pwsh(?:\.exe)?|/bin/sh|bash\s+-c)", re.IGNORECASE),
        "References shell / PowerShell / cmd",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.ffi_require",
        Severity.CRITICAL,
        re.compile(r"""require\s*\(\s*['"]ffi['"]\s*\)""", re.IGNORECASE),
        "Requires LuaJIT FFI module",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.ffi_cdef",
        Severity.CRITICAL,
        re.compile(r"\bffi\.cdef\s*\(", re.IGNORECASE),
        "Defines native C bindings via ffi.cdef",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.ffi_load",
        Severity.CRITICAL,
        re.compile(r"\bffi\.load\s*\(", re.IGNORECASE),
        "Loads a native library via ffi.load",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.network_url",
        Severity.HIGH,
        re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE),
        "Contains an HTTP(S) URL",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.socket",
        Severity.HIGH,
        re.compile(r"""(?:require\s*\(\s*['"]socket['"]\s*\)|\bsocket\.(?:connect|http|tcp|udp)\b)""", re.IGNORECASE),
        "Uses network sockets",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.download_tools",
        Severity.HIGH,
        re.compile(r"\b(?:curl|wget|DownloadString|WebClient|XMLHttpRequest|Invoke-WebRequest)\b", re.IGNORECASE),
        "References download / HTTP client APIs",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.absolute_windows_path",
        Severity.HIGH,
        re.compile(r"[A-Za-z]:\\(?:Users|Windows|Program Files|Temp)[^'\"\n]*", re.IGNORECASE),
        "References an absolute Windows system/user path",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.appdata",
        Severity.HIGH,
        re.compile(r"%APPDATA%|%LOCALAPPDATA%|%TEMP%|\\AppData\\", re.IGNORECASE),
        "References AppData / temp environment paths",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.registry",
        Severity.HIGH,
        re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|\\\\Software\\\\Microsoft", re.IGNORECASE),
        "References Windows registry paths",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.base64_blob",
        Severity.MEDIUM,
        re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
        "Contains a long base64-like string (possible obfuscation)",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.hex_escape_dense",
        Severity.MEDIUM,
        re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}"),
        "Dense hex-escaped string (possible obfuscation)",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.string_char_chain",
        Severity.MEDIUM,
        re.compile(r"string\.char\s*\(", re.IGNORECASE),
        "Builds strings via string.char (common obfuscation)",
        frozenset({"lua"}),
    ),
    PatternRule(
        "script.js_eval",
        Severity.HIGH,
        re.compile(r"\beval\s*\(|\bFunction\s*\(", re.IGNORECASE),
        "Uses eval / Function (dynamic JS execution)",
        frozenset({"js"}),
    ),
]


def _lang_for(path: str) -> str | None:
    lower = path.lower().replace("\\", "/")
    if lower.endswith(".lua"):
        return "lua"
    if lower.endswith(".js"):
        return "js"
    return None


def _under_ui(path: str) -> bool:
    parts = path.lower().replace("\\", "/").split("/")
    return "ui" in parts[:-1]


def _severity_for(rule: PatternRule, path: str) -> Severity:
    if rule.languages == frozenset({"js"}) or "js" in rule.languages:
        if _lang_for(path) == "js" and _under_ui(path) and rule.rule_id in {
            "script.network_url",
            "script.download_tools",
        }:
            # UI apps often talk to local/game APIs; keep but lower urgency for plain URLs.
            if rule.rule_id == "script.network_url":
                return Severity.LOW
    return rule.severity


def _truncate(text: str, limit: int = 120) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def scan_script_patterns(members: list[ZipMember], zf) -> list[Finding]:
    findings: list[Finding] = []

    for member in members:
        if member.is_dir:
            continue
        lang = _lang_for(member.name)
        if not lang:
            continue

        text = read_text(zf, member.name)
        if text is None:
            continue

        lines = text.splitlines()
        for rule in RULES:
            if lang not in rule.languages:
                continue
            for line_no, line in enumerate(lines, start=1):
                match = rule.pattern.search(line)
                if not match:
                    continue
                findings.append(
                    Finding(
                        severity=_severity_for(rule, member.name),
                        rule_id=rule.rule_id,
                        path=member.name.replace("\\", "/"),
                        detail=rule.detail,
                        line=line_no,
                        snippet=_truncate(line),
                    )
                )
                # One hit per rule per file is enough to avoid noise from repeated patterns
                # except for distinct high-signal rules — keep first match only per rule/file.
                break

    return findings
