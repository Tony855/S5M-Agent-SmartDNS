#!/usr/bin/env python3
import pathlib
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-source-archive.py"


def run_case(entries, should_pass):
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        archive_path = root / "source.zip"
        destination = root / "extract"
        outside = root / "outside.txt"
        outside.write_text("unchanged", encoding="utf-8")
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name, payload, mode in entries:
                info = zipfile.ZipInfo(name)
                if mode is not None:
                    info.external_attr = mode << 16
                archive.writestr(info, payload)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(archive_path), str(destination)],
            capture_output=True,
            text=True,
        )
        assert (result.returncode == 0) == should_pass, result.stderr
        assert outside.read_text(encoding="utf-8") == "unchanged"
        if should_pass:
            assert (destination / "source" / "main.go").is_file()
        else:
            assert not destination.exists()


regular = stat.S_IFREG | 0o644
directory = stat.S_IFDIR | 0o755
symlink = stat.S_IFLNK | 0o777
run_case([
    ("source/", "", directory),
    ("source/main.go", "package main\n", regular),
], True)
for bad_name in (
    "../outside.txt",
    "source/../../outside.txt",
    "/source/main.go",
    r"source\..\outside.txt",
    "source//main.go",
    "source/./main.go",
):
    run_case([(bad_name, "bad", regular)], False)
run_case([("source/link", "outside.txt", symlink)], False)
run_case([
    ("source/main.go", "first", regular),
    ("source/main.go", "second", regular),
], False)
run_case([
    ("source/file", "file", regular),
    ("source/file/child", "child", regular),
], False)

print("Source archive validation security tests passed.")
