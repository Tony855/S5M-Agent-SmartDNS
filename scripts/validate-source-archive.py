#!/usr/bin/env python3
"""Validate and safely extract the bundled S5M-Server source ZIP."""

from __future__ import annotations

import argparse
import pathlib
import stat
import sys
import zipfile

MAX_ENTRIES = 10_000
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_TOTAL_SIZE = 150 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000


def validate_and_extract(archive_path: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"destination already exists: {destination}")

    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            raise ValueError("source archive has an invalid entry count")

        seen: dict[str, bool] = {}
        total_size = 0
        for info in infos:
            name = info.filename
            if not name or "\x00" in name or "\\" in name or name.startswith("/"):
                raise ValueError(f"unsafe archive path: {name!r}")

            is_dir = info.is_dir()
            raw_name = name[:-1] if is_dir else name
            parts = raw_name.split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise ValueError(f"unsafe archive path: {name!r}")
            if parts[0] != "source":
                raise ValueError(f"unexpected archive root: {name!r}")

            normalized = "/".join(parts)
            if normalized in seen:
                raise ValueError(f"duplicate archive path: {name!r}")

            mode = (info.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"non-regular archive entry: {name!r}")
            if kind == stat.S_IFDIR and not is_dir:
                raise ValueError(f"directory entry missing trailing slash: {name!r}")
            if kind == stat.S_IFREG and is_dir:
                raise ValueError(f"regular file marked as directory: {name!r}")

            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                if parent in seen and not seen[parent]:
                    raise ValueError(f"archive path descends through a file: {name!r}")
            if not is_dir and any(path.startswith(normalized + "/") for path in seen):
                raise ValueError(f"archive file conflicts with child path: {name!r}")

            if info.file_size < 0 or info.file_size > MAX_FILE_SIZE:
                raise ValueError(f"archive entry too large: {name!r}")
            total_size += info.file_size
            if total_size > MAX_TOTAL_SIZE:
                raise ValueError("source archive expands beyond 150 MiB")
            if info.flag_bits & 0x1:
                raise ValueError(f"encrypted archive entry is not supported: {name!r}")
            if info.file_size and (
                info.compress_size == 0
                or info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                raise ValueError(f"archive entry compression ratio is excessive: {name!r}")

            seen[normalized] = is_dir

        bad_member = archive.testzip()
        if bad_member is not None:
            raise ValueError(f"archive CRC check failed: {bad_member!r}")

        destination.mkdir(parents=True, exist_ok=False)
        archive.extractall(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    try:
        validate_and_extract(args.archive, args.destination)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"source archive rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
