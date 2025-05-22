import os
import sys
import subprocess
import socket
import json
import win32pipe
import win32file
import pywintypes
import time
import logging
import threading

# Konfiguration
PIPE_NAME = r"\\.\pipe\WindowsUpdateTweakerPipe"
SERVICE_NAME = "WindowsUpdateTweakerService"
SERVICE_EXECUTABLE = "wut_system_service.py"

class SystemServiceClient:
    """Client für die Kommunikation mit dem Windows Update Tweaker System Service"""
    
    def __init__(self, log_function=None):
        """Initialisiert den Client"""
        self.log_function = log_function or (lambda msg: None)
        self.service_installed = False
        self.service_running = False
        self._check_service_status()
    
    def _log(self, message):
        """Protokolliert eine Nachricht"""
        if self.log_function:
            self.log_function(f"SystemServiceClient: {message}")
    
    def _check_service_status(self):
        """Prüft, ob der Dienst installiert und aktiv ist"""
        try:
            # Prüfe, ob der Dienst installiert ist
            result = self._run_command(f'sc query "{SERVICE_NAME}"')
            self.service_installed = result["returncode"] == 0
            
            # Prüfe, ob der Dienst läuft
            if self.service_installed:
                self.service_running = "RUNNING" in result["stdout"]
            else:
                self.service_running = False
            
            self._log(f"Service status: installed={self.service_installed}, running={self.service_running}")
            return self.service_installed and self.service_running
        except Exception as e:
            self._log(f"Error checking service status: {e}")
            self.service_installed = False
            self.service_running = False
            return False
    
    def ensure_service_running(self):
        """Stellt sicher, dass der Dienst installiert und aktiv ist"""
        if not self._check_service_status():
            if not self.service_installed:
                self._install_service()
            if not self.service_running:
                self._start_service()
            # Erneut prüfen
            return self._check_service_status()
        return True
    
    def _install_service(self):
        """Installiert den Dienst"""
        self._log("Installing service...")
        
        # Bestimme den Pfad zur Dienstdatei
        script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        service_path = os.path.join(script_dir, SERVICE_EXECUTABLE)
        
        if not os.path.exists(service_path):
            self._log(f"Service executable not found at {service_path}")
            return False
        
        # Installiere den Dienst
        python_exe = sys.executable
        cmd = f'"{python_exe}" "{service_path}" install'
        result = self._run_command(cmd)
        
        if result["returncode"] == 0:
            self._log("Service installed successfully")
            self.service_installed = True
            return True
        else:
            self._log(f"Failed to install service: {result['stderr']}")
            return False
    
    def _start_service(self):
        """Startet den Dienst"""
        self._log("Starting service...")
        
        # Starte den Dienst
        cmd = f'sc start "{SERVICE_NAME}"'
        result = self._run_command(cmd)
        
        if result["returncode"] == 0:
            self._log("Service started successfully")
            self.service_running = True
            # Kurze Pause, um dem Dienst Zeit zum Starten zu geben
            time.sleep(1)
            return True
        else:
            self._log(f"Failed to start service: {result['stderr']}")
            return False
    
    def _run_command(self, cmd):
        """Führt einen Shell-Befehl aus und gibt das Ergebnis zurück"""
        try:
            # Führe Befehl aus und erfasse Ausgabe
            process = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )
            
            result = {
                "stdout": process.stdout.strip(),
                "stderr": process.stderr.strip(),
                "returncode": process.returncode
            }
            
            return result
        except Exception as e:
            self._log(f"Exception executing command {cmd}: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    
    def send_request(self, operation, params=None, max_retries=2):
        """Sendet eine Anfrage an den Dienst und gibt die Antwort zurück"""
        if params is None:
            params = {}
        
        # Stelle sicher, dass der Dienst läuft
        if not self.ensure_service_running():
            return {
                "status": "error",
                "message": "Service is not running and could not be started"
            }
        
        # Bereite Anfrage vor
        request = {
            "operation": operation,
            "params": params
        }
        request_data = json.dumps(request).encode('utf-8')
        
        # Sende Anfrage an den Dienst
        retries = 0
        while retries <= max_retries:
            try:
                # Verbinde mit Named Pipe
                pipe_handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                
                # Setze Pipe-Modus
                win32pipe.SetNamedPipeHandleState(
                    pipe_handle,
                    win32pipe.PIPE_READMODE_MESSAGE,
                    None,
                    None
                )
                
                # Sende Anfrage
                self._log(f"Sending request: {request}")
                win32file.WriteFile(pipe_handle, request_data)
                
                # Lese Antwort
                result, data = win32file.ReadFile(pipe_handle, 4096)
                response = json.loads(data.decode('utf-8'))
                
                # Schließe Pipe
                win32file.CloseHandle(pipe_handle)
                
                self._log(f"Received response: {response}")
                return response
                
            except pywintypes.error as e:
                if e.winerror == 2:  # ERROR_FILE_NOT_FOUND
                    self._log("Pipe not found, service might not be ready yet")
                elif e.winerror == 109:  # ERROR_BROKEN_PIPE
                    self._log("Pipe connection broken")
                else:
                    self._log(f"Pipe error: {e}")
                
                # Schließe Pipe-Handle, falls vorhanden
                try:
                    if 'pipe_handle' in locals():
                        win32file.CloseHandle(pipe_handle)
                except:
                    pass
                
                # Erhöhe Retry-Zähler
                retries += 1
                
                if retries <= max_retries:
                    self._log(f"Retrying ({retries}/{max_retries})...")
                    # Stelle sicher, dass der Dienst läuft
                    self.ensure_service_running()
                    # Warte kurz vor dem nächsten Versuch
                    time.sleep(1)
                else:
                    self._log("Max retries reached")
                    return {
                        "status": "error",
                        "message": f"Failed to communicate with service: {e}"
                    }
            
            except Exception as e:
                self._log(f"Error sending request: {e}")
                
                # Schließe Pipe-Handle, falls vorhanden
                try:
                    if 'pipe_handle' in locals():
                        win32file.CloseHandle(pipe_handle)
                except:
                    pass
                
                return {
                    "status": "error",
                    "message": f"Error: {e}"
                }
    
    def test_connection(self):
        """Testet die Verbindung zum Dienst"""
        return self.send_request("test_connection")
    
    def disable_scheduled_task(self, task_name):
        """Deaktiviert eine geplante Aufgabe mit SYSTEM-Rechten"""
        return self.send_request("disable_scheduled_task", {"task_name": task_name})
    
    def enable_scheduled_task(self, task_name):
        """Aktiviert eine geplante Aufgabe mit SYSTEM-Rechten"""
        return self.send_request("enable_scheduled_task", {"task_name": task_name})
    
    def get_scheduled_task_status(self, task_name):
        """Ermittelt den Status einer geplanten Aufgabe mit SYSTEM-Rechten"""
        response = self.send_request("get_scheduled_task_status", {"task_name": task_name})
        if response["status"] == "success" and "task_status" in response:
            return response["task_status"]
        return "Unknown"
    
    def disable_service(self, service_name):
        """Deaktiviert einen Windows-Dienst mit SYSTEM-Rechten"""
        return self.send_request("disable_service", {"service_name": service_name})
    
    def enable_service(self, service_name, start_type="manual"):
        """Aktiviert einen Windows-Dienst mit SYSTEM-Rechten"""
        return self.send_request("enable_service", {
            "service_name": service_name,
            "start_type": start_type
        })
