from cx_Freeze import setup, Executable

include_files = ['security_engine.db', 'sentinel/assets/DIN.ttf', 'sentinel/assets/FuturaLightCondensedBT.ttf']

setup(
    name="Sharva Prime Malware Hunter",
    version="0.1",
    description="Malware detection and quarantine tool with a custom signature database.",
    options={'build_exe': {'include_files': include_files}},
    executables=[Executable("app.py", target_name='SharvaPrime.exe', icon='trident.ico')]
)