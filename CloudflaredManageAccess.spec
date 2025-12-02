# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/a920634/Documents/Travaux/Cloudflared-Tunnel-Manager/CloudflaredManageAccess.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\a920634\\AppData\\Local\\Programs\\Python\\Python314\\tcl\\tcl8', 'tcl8'), ('C:\\Users\\a920634\\AppData\\Local\\Programs\\Python\\Python314\\tcl\\tcl8.6', 'tcl8.6'), ('C:\\Users\\a920634\\AppData\\Local\\Programs\\Python\\Python314\\tcl\\tk8.6', 'tk8.6'), ('C:/Users/a920634/Documents/Travaux/Cloudflared-Tunnel-Manager/ico', 'ico')],
    hiddenimports=['tkinter', 'tkinter.filedialog'],
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
    name='CloudflaredManageAccess',
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
    icon=['C:\\Users\\a920634\\Documents\\Travaux\\Cloudflared-Tunnel-Manager\\ico\\cloudflared.ico'],
)
