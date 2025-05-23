#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Update Tweaker - PyInstaller Service Compilation Script
--------------------------------------------------------------
Dieses Skript kompiliert den Windows Update Tweaker System Service
zu einer eigenständigen EXE-Datei mit PyInstaller.

Führen Sie dieses Skript aus, um die Service-EXE zu erstellen.
"""

import os
import sys
import subprocess
import shutil

# Konfiguration
SERVICE_SCRIPT = "wut_system_service.py"
OUTPUT_NAME = "wut_system_service"
PYINSTALLER_ARGS = [
    "--onefile",
    "--noconsole",
    "--hidden-import=win32timezone",
    "--hidden-import=win32serviceutil",
    "--hidden-import=win32service",
    "--hidden-import=win32event",
    "--hidden-import=servicemanager",
    f"--name={OUTPUT_NAME}",
    SERVICE_SCRIPT
]

def compile_service():
    """Kompiliert den Service mit PyInstaller"""
    print(f"Kompiliere {SERVICE_SCRIPT} zu einer eigenständigen EXE-Datei...")
    
    # Prüfe, ob PyInstaller installiert ist
    try:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("PyInstaller ist installiert.")
    except (subprocess.SubprocessError, FileNotFoundError):
        print("PyInstaller ist nicht installiert. Installiere PyInstaller...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pyinstaller"],
                check=True
            )
            print("PyInstaller wurde erfolgreich installiert.")
        except subprocess.SubprocessError as e:
            print(f"Fehler beim Installieren von PyInstaller: {e}")
            return False
    
    # Führe PyInstaller aus
    try:
        cmd = [sys.executable, "-m", "PyInstaller"] + PYINSTALLER_ARGS
        print(f"Führe Befehl aus: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("PyInstaller-Ausgabe:")
        print(process.stdout)
        
        if process.stderr:
            print("PyInstaller-Fehler:")
            print(process.stderr)
        
        # Prüfe, ob die EXE erstellt wurde
        exe_path = os.path.join("dist", f"{OUTPUT_NAME}.exe")
        if os.path.exists(exe_path):
            print(f"EXE erfolgreich erstellt: {os.path.abspath(exe_path)}")
            
            # Kopiere die EXE in das aktuelle Verzeichnis
            shutil.copy2(exe_path, f"{OUTPUT_NAME}.exe")
            print(f"EXE in das aktuelle Verzeichnis kopiert: {os.path.abspath(f'{OUTPUT_NAME}.exe')}")
            
            return True
        else:
            print(f"Fehler: EXE wurde nicht gefunden: {exe_path}")
            return False
    
    except subprocess.SubprocessError as e:
        print(f"Fehler beim Ausführen von PyInstaller: {e}")
        return False

if __name__ == "__main__":
    if compile_service():
        print("Kompilierung erfolgreich abgeschlossen.")
        sys.exit(0)
    else:
        print("Kompilierung fehlgeschlagen.")
        sys.exit(1)
