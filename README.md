# Simple Mod Scanner

A **simple, best-effort** heuristic checker for [BeamNG.drive](https://www.beamng.com/) mod `.zip` files.

It looks for obviously suspicious stuff (executables, shell/FFI patterns, odd packing) **in memory** — nothing is extracted to disk.

## Important — read this

**This is not antivirus.**  
**A CLEAN result does not mean a mod is safe.**  
**A SUSPICIOUS / MALICIOUS result does not always mean it is malware.**

This tool uses basic static pattern matching. Clever malware can hide from it. False positives happen. You are responsible for what you install.

BeamNG itself is heavily sandboxed — many classic `os.execute`-style tricks are blocked in-game. This scanner still flags them as high-signal *intent*, and focuses on patterns like WebSockets, remote script loads, FFI, and absolute file writes.

Use it as a quick second look only — keep real antivirus installed, and treat random Discord/forum mods with caution.

We test with **synthetic fixtures we wrote ourselves**. We do not distribute real malware samples.

## Features

- Scan a single `.zip` or a folder of mods
- Flag dangerous extensions (`.exe`, `.dll`, `.bat`, …) and PE (`MZ`) payloads
- Flag suspicious patterns in `.lua` / `.js` / `.html`
- Check for non-standard BeamNG folder packing
- Color-coded verdicts: **CLEAN** / **SUSPICIOUS** / **MALICIOUS**
- Export a JSON report

## Install (Windows — easiest)

1. Install **Python 3.10+** from https://www.python.org/downloads/  
   (check **Add python.exe to PATH** during setup)
2. Download / clone this repo
3. Double-click **`install.bat`**
4. Double-click **`run.bat`** to open the app

`run.bat` will run `install.bat` automatically if needed.

### Manual install (optional)

```powershell
git clone https://github.com/rod-dor/simple-mod-scanner.git
cd simple-mod-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python -m simple_mod_scanner
```

## Use

1. Browse a `.zip` or folder
2. Click **Scan**
3. Inspect findings
4. Optionally export JSON

## Verdicts

| Verdict | Meaning |
|---|---|
| CLEAN | No medium/high/critical hits (still not a safety guarantee) |
| SUSPICIOUS | Worth a closer look — network pipes, dynamic `load(cmd)`, obfuscation, odd JS paths, etc. Often legit advanced mods |
| MALICIOUS | Only **hard** signals: Windows executables/PE droppers, `os.execute` / `io.popen`, FFI / `package.loadlib`, ActiveX/WScript, shell binaries, zip path traversal |

**MALICIOUS is intentionally rare.** Things like WebSocket (live audio / DRM), `load(cmd)` triggers, or obfuscated Lua are **SUSPICIOUS**, not automatic malware.

## Found a malicious mod?

If you hit a mod that looks **actually malicious** (not just SUSPICIOUS / a false positive), contact me on Discord so I can inspect it and improve the scanner:

**Discord: `@rodomil`**

Please include the mod name/source if you can, and preferably the zip or a scan report export. Do **not** post malware publicly in GitHub issues.

## Development

```powershell
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE). Provided as-is, with no warranty.
