from __future__ import annotations

import re
from dataclasses import dataclass

from simple_mod_scanner.models import Finding, Severity
from simple_mod_scanner.zip_reader import ZipMember, read_text


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    detail: str
    languages: frozenset[str]
    category: str = "high-signal"  # or false-positive-prone


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
        # (?<![\w.]) avoids matching extensions.load(...).
        # Bare load('ExtensionName') is filtered later as BeamNG extension loading.
        re.compile(r"(?i)(?<![\w.])(?:loadstring\s*\(|load\s*\()"),
        "Dynamic code loading (loadstring / load of code)",
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
        Severity.LOW,  # demoted; escalate if file also uses network APIs
        re.compile(r"https?://[^\s'\"`<>]+", re.IGNORECASE),
        "Contains an HTTP(S) URL (often docs/credits — low alone)",
        frozenset({"lua", "js", "html"}),
        category="false-positive-prone",
    ),
    PatternRule(
        "script.websocket",
        Severity.HIGH,
        re.compile(r"\bWebSocket\s*\(", re.IGNORECASE),
        "Opens a WebSocket connection (possible remote control / phone-home)",
        frozenset({"js", "html"}),
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
        "script.risky_file_write",
        Severity.HIGH,
        re.compile(
            r"(?i)(?:jsonWriteFile|writeFile|io\.open)\s*\([^;]{0,200}"
            r"(?:[A-Za-z]:\\|%APPDATA%|%LOCALAPPDATA%|%TEMP%|/Users/|\\Users\\|Documents\\)",
        ),
        "Writes a file using an absolute / user-profile path (high-signal)",
        frozenset({"lua"}),
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
    # --- Medium: obfuscation ---
    PatternRule(
        "script.base64_blob",
        Severity.MEDIUM,
        re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
        "Contains a very long base64-like string (possible obfuscation)",
        frozenset({"lua", "js"}),
        category="false-positive-prone",
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
        "Builds strings via string.char (common obfuscation; ignored unless frequent in file)",
        frozenset({"lua"}),
        category="false-positive-prone",
    ),
]


_EVAL_IDENTIFIER_RE = re.compile(r"(?i)\beval\s*\(\s*[A-Za-z_$][\w$]*\s*\)")
# BeamNG extension loader: load('myExtension') / load("my.extension")
_BEAM_EXT_LOAD_RE = re.compile(
    r"(?i)(?<![\w.])load\s*\(\s*['\"][A-Za-z_][\w.]*['\"]\s*\)"
)
_NETWORK_API_RE = re.compile(
    r"(?i)\b(?:WebSocket\s*\(|XMLHttpRequest\b|\bfetch\s*\(|socket\.(?:connect|http|tcp|udp)\b|"
    r"http\.request\s*\(|require\s*\(\s*['\"]socket)"
)
_OBFUSCATED_LUA_RE = re.compile(
    r"(?i)while\s+true\b.*?\bv0\b.*?\bv1\b|\bv0\s*=\s*\{.*?while\s+true\b",
    re.DOTALL,
)


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
    # HTML comments and odd credit lines like: <! DO NOT USE ... https://...>
    if stripped.startswith("<!") and not stripped.lower().startswith("<!doctype"):
        return True
    return (
        stripped.startswith("//")
        or stripped.startswith("--")
        or stripped.startswith("#")
        or stripped.startswith("<!--")
    )


_BENIGN_URL_RE = re.compile(
    r"(?:"
    r"beamng\.com|"
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
    lower = line.lower()
    if "data:image" in lower or "data:application/octet" in lower:
        return True
    if _is_comment_line(line):
        return True
    return False


def _is_eval_identifier_lookup(line: str) -> bool:
    return _EVAL_IDENTIFIER_RE.search(line) is not None and "Function" not in line


def _is_beam_extension_load(line: str) -> bool:
    """True for load('extName') — BeamNG extension API, not Lua loadstring."""
    if "loadstring" in line.lower():
        return False
    return _BEAM_EXT_LOAD_RE.search(line) is not None and "[[" not in line


def _severity_for(rule: PatternRule, path: str, line: str = "", file_has_network_api: bool = False) -> Severity:
    if rule.rule_id == "script.js_eval" and _is_eval_identifier_lookup(line):
        return Severity.LOW
    if rule.rule_id == "script.network_url":
        if file_has_network_api:
            return Severity.HIGH
        return Severity.LOW
    return rule.severity


def _detail_for(rule: PatternRule, line: str) -> str:
    prefix = f"[{rule.category}] "
    if rule.rule_id == "script.js_eval" and _is_eval_identifier_lookup(line):
        return prefix + "eval(identifier) variable lookup (common in gauge UI; low risk vs eval of strings)"
    if rule.rule_id == "script.loadstring" and _is_beam_extension_load(line):
        return prefix + "BeamNG extension load('name') — ignored as dynamic-code signal"
    return prefix + rule.detail


def _truncate(text: str, limit: int = 120) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _file_obfuscation_finding(path: str, text: str) -> Finding | None:
    if not path.lower().endswith(".lua"):
        return None
    # Dense obfuscators: while-true control flow + v0/v1 locals, usually one huge line
    lines = text.splitlines()
    long_lines = sum(1 for line in lines if len(line) > 400)
    if long_lines < 1:
        return None
    if not re.search(r"(?i)\bwhile\s+true\b", text):
        return None
    if not re.search(r"\bv0\b", text) or not re.search(r"\bv1\b", text):
        return None
    return Finding(
        severity=Severity.MEDIUM,
        rule_id="script.obfuscated_lua",
        path=path.replace("\\", "/"),
        detail="[high-signal] Obfuscated Lua (dense v0/v1 + while-true) — review manually; not proof of malware",
        line=next((i for i, line in enumerate(lines, 1) if len(line) > 400), 1),
        snippet=_truncate(next((line for line in lines if len(line) > 400), text[:120])),
    )


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
        file_has_network_api = bool(_NETWORK_API_RE.search(text))
        string_char_hits = len(re.findall(r"(?i)string\.char\s*\(", text))

        for rule in RULES:
            if lang not in rule.languages:
                continue
            if rule.rule_id == "script.string_char_chain" and string_char_hits < 3:
                continue

            best: Finding | None = None
            for line_no, line in enumerate(lines, start=1):
                match = rule.pattern.search(line)
                if not match:
                    continue
                if rule.rule_id == "script.network_url" and _should_skip_network_url(line):
                    continue
                if rule.rule_id == "script.base64_blob" and _should_skip_base64(line):
                    continue
                if rule.rule_id == "script.loadstring" and _is_beam_extension_load(line):
                    continue
                if _is_comment_line(line) and rule.rule_id in {
                    "script.download_tools",
                    "script.http_client_with_url",
                    "script.atob_decode",
                    "script.websocket",
                    "script.risky_file_write",
                }:
                    continue
                candidate = Finding(
                    severity=_severity_for(rule, member.name, line, file_has_network_api),
                    rule_id=rule.rule_id,
                    path=member.name.replace("\\", "/"),
                    detail=_detail_for(rule, line),
                    line=line_no,
                    snippet=_truncate(line),
                )
                if best is None or candidate.severity.rank > best.severity.rank:
                    best = candidate
                if rule.rule_id != "script.js_eval":
                    break
                if candidate.severity.rank >= Severity.HIGH.rank:
                    break
            if best is not None:
                findings.append(best)

        obf = _file_obfuscation_finding(member.name, text)
        if obf is not None:
            findings.append(obf)

    return findings
