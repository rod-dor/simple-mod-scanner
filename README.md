# BeamNG Mod Scanner

Scan [BeamNG.drive](https://www.beamng.com/) mod `.zip` files for malware and suspicious code **in memory** — nothing is extracted to disk.

This is a desktop app (CustomTkinter) aimed at players who download mods from forums, Discord, or random links and want a quick second opinion before installing.

## Features

- Scan a single `.zip` or an entire folder of mods
- Detect dangerous extensions (`.exe`, `.dll`, `.bat`, `.vbs`, …) and PE (`MZ`) payloads
- Flag suspicious patterns in `.lua` / `.js` (shell execution, FFI, downloads, obfuscation)
- Check for non-standard BeamNG folder packing (`vehicles/`, `lua/`, `ui/`, …)
- Color-coded verdicts: **CLEAN** / **SUSPICIOUS** / **MALICIOUS**
- Export a JSON report

## Disclaimer

This tool uses **static heuristics**. It is **not** antivirus software and will not catch every threat. A clean result does not guarantee a mod is safe; a suspicious result does not always mean malware (some false positives are expected). Use common sense and keep a real AV product installed.

## Install (Windows — easiest)

1. Install **Python 3.10+** from https://www.python.org/downloads/  
   (check **Add python.exe to PATH** during setup)
2. Download / clone this repo
3. Double-click **`install.bat`**
4. Double-click **`run.bat`** whenever you want to open the scanner

`run.bat` will run `install.bat` automatically if you skip step 3.

### Manual install (optional)

```powershell
git clone https://github.com/rod-dor/beamng-mod-scanner.git
cd beamng-mod-scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python -m beamng_mod_scanner
```

## Use

1. Click **Browse file** or **Browse folder**
2. Click **Scan**
3. Select a result to inspect findings
4. Optionally **Export JSON**

## Verdicts

| Verdict | Meaning |
|---|---|
| CLEAN | No medium/high/critical findings |
| SUSPICIOUS | Medium or high findings (odd layout, network URLs, obfuscation, …) |
| MALICIOUS | Critical findings (executables, shell/FFI, path traversal, …) |

## Development

```powershell
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
