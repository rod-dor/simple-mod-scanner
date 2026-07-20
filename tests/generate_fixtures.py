"""Generate tiny synthetic BeamNG mod ZIP fixtures for tests."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixtures"


def _write_zip(path: Path, files: dict[str, bytes | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            zf.writestr(name, data)


def main() -> None:
    FIX.mkdir(parents=True, exist_ok=True)

    _write_zip(
        FIX / "clean_vehicle.zip",
        {
            "vehicles/testcar/info.json": '{"Name":"Test Car"}\n',
            "vehicles/testcar/testcar.jbeam": '{"testcar":{}}\n',
        },
    )

    _write_zip(
        FIX / "wrapped_mod.zip",
        {
            "MyCoolCar/vehicles/coolcar/info.json": '{"Name":"Cool"}\n',
        },
    )

    _write_zip(
        FIX / "with_exe.zip",
        {
            "vehicles/evil/info.json": "{}\n",
            "vehicles/evil/helper.exe": b"MZ" + b"\x00" * 64,
        },
    )

    long_b64 = "A" * 100 + "=="
    _write_zip(
        FIX / "malicious_lua.zip",
        {
            "lua/ge/extensions/evil.lua": (
                "local ffi = require('ffi')\n"
                "os.execute('cmd.exe /c whoami')\n"
                f"local payload = '{long_b64}'\n"
            ),
        },
    )

    _write_zip(
        FIX / "suspicious_js.zip",
        {
            "ui/modules/apps/demo/app.js": "console.log('ok');\n",
            "scripts/weird.js": "eval('alert(1)');\n",
        },
    )

    print(f"Wrote fixtures to {FIX}")


if __name__ == "__main__":
    main()
