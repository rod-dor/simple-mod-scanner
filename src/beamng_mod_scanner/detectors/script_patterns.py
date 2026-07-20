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
    # --- Critical: native / process execution ---
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
        # Avoid bare load( — common and often legitimate in Lua.
        re.compile(r"\bloadstring\s*\(|\bload\s*\(\s*['\"]", re.IGNORECASE),
        "Dynamic code loading from a string (loadstring / load \"...\")",
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
        frozenset({"lua", "js", "html"}),
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
        "script.wscript_activex",
        Severity.CRITICAL,
        re.compile(r"\b(?:WScript|ActiveXObject|Shell\.Application)\b", re.IGNORECASE),
        "References Windows scripting / ActiveX APIs (not used by normal BeamNG UI)",
        frozenset({"js", "html"}),
    ),
    # --- High: network / remote code ---
    PatternRule(
        "script.network_url",
        Severity.HIGH,
        re.compile(r"https?://[^\s'\"`<>]+", re.IGNORECASE),
        "Contains an HTTP(S) URL",
        frozenset({"lua", "js", "html"}),
    ),
    PatternRule(
        "script.socket",
        Severity.HIGH,
        re.compile(
            r"""(?:require\s*\(\s*['"]socket(?:\.http)?['"]\s*\)|\bsocket\.(?:connect|http|tcp|udp)\b|\bhttp\.request\s*\()""",
            re.IGNORECASE,
        ),
        "Uses network sockets / HTTP request APIs",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.download_tools",
        Severity.HIGH,
        # Bare XMLHttpRequest/fetch moved to http_client_with_url (needs URL context).
        re.compile(r"\b(?:curl|wget|DownloadString|WebClient|Invoke-WebRequest)\b", re.IGNORECASE),
        "References download / HTTP client tooling",
        frozenset({"lua", "js", "html"}),
    ),
    PatternRule(
        "script.http_client_with_url",
        Severity.HIGH,
        re.compile(
            r"(?:(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\()[^\n]{0,160}https?://)"
            r"|(?:https?://[^\n]{0,160}(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\())",
            re.IGNORECASE,
        ),
        "HTTP client API used together with an HTTP(S) URL",
        frozenset({"js", "html"}),
    ),
    PatternRule(
        "script.remote_script_src",
        Severity.HIGH,
        re.compile(r"""<\s*script[^>]+src\s*=\s*['"]https?://""", re.IGNORECASE),
        "Loads a remote <script src=\"http(s)://...\">",
        frozenset({"html"}),
    ),
    PatternRule(
        "script.document_write_script",
        Severity.HIGH,
        re.compile(r"document\.write\s*\([^)]*<\s*script", re.IGNORECASE),
        "Injects a script via document.write",
        frozenset({"js", "html"}),
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
        "script.js_eval",
        Severity.HIGH,
        # eval(...) case-insensitive; Function(...) constructor must stay case-sensitive
        # so Angular/JS `function ()` callbacks are not flagged.
        re.compile(r"(?i:\beval\s*\()|(?<![A-Za-z0-9_])Function\s*\("),
        "Uses eval / Function (dynamic JS execution)",
        frozenset({"js", "html"}),
    ),
    PatternRule(
        "script.atob_decode",
        Severity.HIGH,
        re.compile(r"\batob\s*\(", re.IGNORECASE),
        "Decodes base64 via atob (common malware staging step)",
        frozenset({"js", "html"}),
    ),
    # --- Medium: obfuscation (carefully filtered at match time) ---
    PatternRule(
        "script.base64_blob",
        Severity.MEDIUM,
        re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
        "Contains a very long base64-like string (possible obfuscation)",
        frozenset({"lua", "js"}),
    ),
    PatternRule(
        "script.hex_escape_dense",
        Severity.MEDIUM,
        re.compile(r"(?:\\x[0-9A-Fa-f]{2}){12,}"),
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
]


def _lang_for(path: str) -> str | None:
    lower = path.lower().replace("\\", "/")
    if lower.endswith(".lua"):
        return "lua"
    if lower.endswith(".js"):
        return "js"
    if lower.endswith(".html") or lower.endswith(".htm"):
        return "html"
    return None


def _under_ui(path: str) -> bool:
    parts = path.lower().replace("\\", "/").split("/")
    return "ui" in parts[:-1]


def _is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return (
        stripped.startswith("//")
        or stripped.startswith("--")
        or stripped.startswith("#")
        or stripped.startswith("<!--")
    )


_BENIGN_URL_RE = re.compile(
    r"(?:"
    r"beamng\.com/bCDDL|"
    r"stackoverflow\.com|"
    r"github\.com|"
    r"developer\.mozilla\.org|"
    r"creativecommons\.org|"
    r"opensource\.org|"
    r"gnu\.org|"
    r"apache\.org|"
    r"wikipedia\.org|"
    r"w3\.org"
    r")",
    re.IGNORECASE,
)


def _should_skip_network_url(line: str) -> bool:
    if _is_comment_line(line):
        return True
    if _BENIGN_URL_RE.search(line):
        return True
    return False


def _should_skip_base64(line: str) -> bool:
    # Gauge/UI code often embeds images as data URIs — not malware.
    lower = line.lower()
    if "data:image" in lower or "data:application/octet" in lower:
        return True
    if _is_comment_line(line):
        return True
    return False


def _severity_for(rule: PatternRule, path: str) -> Severity:
    if rule.rule_id == "script.network_url" and _lang_for(path) in {"js", "html"} and _under_ui(path):
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
                if rule.rule_id == "script.network_url" and _should_skip_network_url(line):
                    continue
                if rule.rule_id == "script.base64_blob" and _should_skip_base64(line):
                    continue
                if _is_comment_line(line) and rule.rule_id in {
                    "script.download_tools",
                    "script.http_client_with_url",
                    "script.atob_decode",
                }:
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
                # One hit per rule per file is enough to avoid noise.
                break

    return findings
