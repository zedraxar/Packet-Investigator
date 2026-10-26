"""Build a windowed one-folder app and optional per-user Inno Setup installer."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iscc", type=Path)
    args = parser.parse_args()
    if (
        sys.platform != "win32"
        or platform.machine().lower() not in {"amd64", "x86_64"}
        or sys.maxsize <= 2**32
    ):
        parser.error("Build on Windows x64 with a 64-bit Python environment.")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    version = importlib.metadata.version("packet-investigator")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--onedir",
            "--windowed",
            "--name",
            "PacketInvestigator",
            "--paths",
            str(ROOT / "src"),
            "--distpath",
            str(output / "app"),
            "--workpath",
            str(output / "work"),
            "--specpath",
            str(output / "work"),
            "--add-data",
            f"{ROOT / 'LICENSE'}{os.pathsep}licenses",
            str(ROOT / "packaging/windows/launch.py"),
        ],
        check=True,
        cwd=ROOT,
    )
    bundle = output / "app/PacketInvestigator"
    (bundle / "PREVIEW.txt").write_text(
        (ROOT / "packaging/windows/PREVIEW.txt").read_text(encoding="utf-8-sig"),
        encoding="utf-8",
    )
    # Preserve dependency license texts and a measured build inventory.
    notices = bundle / "licenses"
    notices.mkdir(exist_ok=True)
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        raise RuntimeError("Python redistribution license is missing.")
    (notices / "Python-LICENSE.txt").write_bytes(python_license.read_bytes())
    inventory = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        inventory.append({"name": name, "version": dist.version})
        for entry in dist.files or ():
            if "license" in str(entry).lower() or "copying" in str(entry).lower():
                source = Path(dist.locate_file(entry))
                if source.is_file():
                    target = notices / name / str(entry)
                    # Keep metadata paths containing ../ inside this directory.
                    if not target.resolve().is_relative_to((notices / name).resolve()):
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
    (bundle / "build-inventory.json").write_text(
        json.dumps(
            {
                "python": sys.version,
                "platform": platform.platform(),
                "packages": sorted(inventory, key=lambda item: item["name"].lower()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if args.iscc:
        subprocess.run(
            [
                str(args.iscc.resolve()),
                f"/DAppVersion={version}",
                f"/DBundleDir={bundle}",
                f"/DInstallerDir={output / 'installer'}",
                str(ROOT / "packaging/windows/installer.iss"),
            ],
            check=True,
        )
        installer = (
            output
            / "installer"
            / f"PacketInvestigator-{version}-desktop-preview-windows-x64-setup.exe"
        )
        digest = hashlib.sha256(installer.read_bytes()).hexdigest()
        installer.with_suffix(".exe.sha256").write_text(
            f"{digest}  {installer.name}\n", encoding="ascii"
        )


if __name__ == "__main__":
    main()
