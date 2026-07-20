from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path


TEXT_EXTENSIONS = {
    ".lua",
    ".js",
    ".json",
    ".txt",
    ".md",
    ".csv",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".jbeam",
    ".pc",
    ".cs",
}


@dataclass(slots=True)
class ZipMember:
    name: str
    is_dir: bool
    size: int


class ZipReadError(Exception):
    pass


def open_mod_zip(path: Path) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise ZipReadError(f"Not a valid ZIP archive: {path.name}") from exc
    except OSError as exc:
        raise ZipReadError(f"Cannot open ZIP: {exc}") from exc

    if zf.namelist() and any(info.flag_bits & 0x1 for info in zf.infolist()):
        zf.close()
        raise ZipReadError(f"Encrypted ZIP is not supported: {path.name}")
    return zf


def list_members(zf: zipfile.ZipFile) -> list[ZipMember]:
    members: list[ZipMember] = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        is_dir = name.endswith("/") or info.is_dir()
        members.append(ZipMember(name=name.rstrip("/") + ("/" if is_dir else ""), is_dir=is_dir, size=info.file_size))
    return members


def read_bytes(zf: zipfile.ZipFile, member_name: str, max_bytes: int = 2_000_000) -> bytes:
    try:
        with zf.open(member_name) as handle:
            return handle.read(max_bytes)
    except RuntimeError as exc:
        raise ZipReadError(f"Cannot read member {member_name}: {exc}") from exc
    except KeyError as exc:
        raise ZipReadError(f"Missing member {member_name}") from exc


def read_text(zf: zipfile.ZipFile, member_name: str, max_bytes: int = 2_000_000) -> str | None:
    raw = read_bytes(zf, member_name, max_bytes=max_bytes)
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def looks_like_text(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    suffix = Path(lower).suffix
    return suffix in TEXT_EXTENSIONS
