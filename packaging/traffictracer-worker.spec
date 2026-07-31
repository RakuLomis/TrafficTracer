# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


repo_root = Path(SPECPATH).parent
worker_name = "traffictracer-worker-x86_64-unknown-linux-gnu"

datas = [
    (str(repo_root / "contracts"), "contracts"),
    (str(repo_root / "complete" / "components.lock.yaml"), "complete"),
]
hiddenimports = [
    *collect_submodules("jsonschema"),
    *collect_submodules("websockets"),
]

analysis = Analysis(
    [str(repo_root / "traffictracer_worker.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name=worker_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
