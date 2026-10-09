# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

SPECDIR = Path(os.path.abspath(SPECPATH))
ROOT = SPECDIR.parent
PAYLOAD = SPECDIR / "_launcher_payload"

datas = [
    (str(PAYLOAD / "runtime"), "runtime"),
    (str(PAYLOAD / "api-server"), "api-server"),
    (str(PAYLOAD / "engine"), "engine"),
]
binaries = []
hiddenimports = ['webview.platforms.winforms', 'webview.platforms.edgechromium']
tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

icon_file = SPECDIR / "icon" / "argus.ico"
icon_path = [str(icon_file)] if icon_file.exists() else []

a = Analysis(
    [str(SPECDIR / "argus-launcher.py")],
    pathex=[str(SPECDIR)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ARGUS-Setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
