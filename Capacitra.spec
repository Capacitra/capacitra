# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller build spec for Capacitra.
#
# NOTE: strip must be False on Windows. Enabling it corrupts python311.dll's
# import table and causes 'Failed to load Python DLL / LoadLibrary: Invalid
# access to memory location' on the target machine.
#
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = [
    'reportlab',
    'reportlab.pdfgen',
    'reportlab.lib.pagesizes',
    'reportlab.lib.styles',
    'reportlab.platypus',
    'reportlab.lib',
    'openpyxl',
    'openpyxl.styles',
    'openpyxl.utils',
    'openpyxl.workbook',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'PIL.ImageTk',
]

# collect_all pulls package data, C extensions, and hidden imports
for pkg in ('reportlab', 'openpyxl', 'PIL'):
    try:
        tmp_datas, tmp_binaries, tmp_hidden = collect_all(pkg)
        datas += tmp_datas
        binaries += tmp_binaries
        hiddenimports += tmp_hidden
    except Exception:
        pass


a = Analysis(
    ['Capacitra.pyw'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'pytest', 'se