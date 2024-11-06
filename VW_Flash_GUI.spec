# VW_Flash_GUI.spec
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['VW_Flash_GUI.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('lib/lzss/lzss.exe', 'lib/lzss/'),
        ('logging.ini', '.'),
        ('data/box_codes.csv', 'data/'),
        ('data/mqb_dsg_key.bin', 'data/'),
        ('data/dtcs.csv', 'data/'),
        ('data/frf.key', 'data/'),
        ('logs/log_config.yaml', 'logs/'),
        ('logs/csv/parameters_22.csv', 'logs/csv'),
        ('logs/csv/parameters_3e_LB6.csv', 'logs/csv'),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='VW_Flash_GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='VW_Flash_GUI'
)

app = BUNDLE(
    coll,
    name='VW_Flash_GUI',
    format='ONEFILE',
    strip=False,
    upx=True,
    upx_exclude=[]
)