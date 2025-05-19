#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Update Tweaker - System Service
--------------------------------------
Ein Windows-Dienst, der mit SYSTEM-Rechten ausgeführt wird, um privilegierte Operationen
für den Windows Update Tweaker durchzuführen.

Dieser Dienst ermöglicht die Verwaltung von geschützten geplanten Aufgaben und anderen
Systemkomponenten, die erhöhte Berechtigungen erfordern.
"""

import os
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import time
import subprocess
import logging
import json
import threading
import win32pipe
import win32file
import pywintypes
import traceback

# Konfiguration
SERVICE_NAME = "WindowsUpdateTweakerService"
SERVICE_DISPLAY_NAME = "Windows Update Tweaker Service"
SERVICE_DESCRIPTION = "Führt privilegierte Operationen für den Windows Update Tweaker aus"
PIPE_NAME = r"\\.\pipe\WindowsUpdateTweakerPipe"
LOG_FILE = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 
                        "WindowsUpdateTweaker", "service_log.txt")

# Logging-Konfiguration
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class WindowsUpdateTweakerService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        socket.setdefaulttimeout(60)
        self.pipe_thread = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        logging.info("Service stopping...")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.is_running = True
        logging.info("Service starting...")
        self.main()

    def main(self):
        """Hauptfunktion des Dienstes"""
        try:
            # Starte Named Pipe Server in einem separaten Thread
            self.pipe_thread = threading.Thread(target=self.run_pipe_server)
            self.pipe_thread.daemon = True
            self.pipe_thread.start()
            
            # Hauptschleife des Dienstes
            while self.is_running:
                # Warte auf Stop-Signal oder führe periodische Aufgaben aus
                rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
            
            # Warte auf Beendigung des Pipe-Threads
            if self.pipe_thread and self.pipe_thread.is_alive():
                self.pipe_thread.join(3.0)  # Warte max. 3 Sekunden
                
            logging.info("Service stopped.")
        except Exception as e:
            logging.error(f"Service error: {e}")
            logging.error(traceback.format_exc())
            self.SvcStop()

    def run_pipe_server(self):
        """Führt den Named Pipe Server aus"""
        logging.info(f"Starting pipe server on {PIPE_NAME}")
        
        while self.is_running:
            try:
                # Erstelle Named Pipe
                pipe_handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    4096,  # Ausgabepuffer
                    4096,  # Eingabepuffer
                    0,     # Standardtimeout
                    None   # Sicherheitsattribute
                )
                
                # Warte auf Client-Verbindung
                logging.info("Waiting for client connection...")
                win32pipe.ConnectNamedPipe(pipe_handle, None)
                logging.info("Client connected.")
                
                # Verarbeite Client-Anfrage in separatem Thread
                client_thread = threading.Thread(
                    target=self.handle_client_connection,
                    args=(pipe_handle,)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                logging.error(f"Pipe server error: {e}")
                logging.error(traceback.format_exc())
                
                # Kurze Pause vor dem nächsten Versuch
                time.sleep(1)
                
                # Wenn der Dienst beendet wird, breche die Schleife ab
                if not self.is_running:
                    break

    def handle_client_connection(self, pipe_handle):
        """Verarbeitet eine Client-Verbindung"""
        try:
            # Lese Anfrage vom Client
            data = self.read_from_pipe(pipe_handle)
            if not data:
                logging.warning("Received empty request from client.")
                self.send_response(pipe_handle, {"status": "error", "message": "Empty request"})
                return
            
            # Verarbeite Anfrage
            logging.info(f"Received request: {data}")
            request = json.loads(data)
            
            # Führe die angeforderte Operation aus
            response = self.process_request(request)
            
            # Sende Antwort an Client
            self.send_response(pipe_handle, response)
            
        except Exception as e:
            logging.error(f"Error handling client request: {e}")
            logging.error(traceback.format_exc())
            try:
                self.send_response(pipe_handle, {
                    "status": "error",
                    "message": str(e)
                })
            except:
                pass
        finally:
            # Schließe Pipe-Verbindung
            try:
                win32pipe.DisconnectNamedPipe(pipe_handle)
                win32file.CloseHandle(pipe_handle)
            except:
                pass

    def read_from_pipe(self, pipe_handle):
        """Liest Daten aus der Named Pipe"""
        try:
            result, data = win32file.ReadFile(pipe_handle, 4096)
            return data.decode('utf-8')
        except pywintypes.error as e:
            if e.winerror == 109:  # ERROR_BROKEN_PIPE
                logging.warning("Client disconnected.")
                return None
            raise

    def send_response(self, pipe_handle, response):
        """Sendet eine Antwort über die Named Pipe"""
        try:
            response_data = json.dumps(response).encode('utf-8')
            win32file.WriteFile(pipe_handle, response_data)
            logging.info(f"Sent response: {response}")
        except Exception as e:
            logging.error(f"Error sending response: {e}")
            raise

    def process_request(self, request):
        """Verarbeitet eine Client-Anfrage und führt die angeforderte Operation aus"""
        try:
            operation = request.get("operation")
            params = request.get("params", {})
            
            if not operation:
                return {"status": "error", "message": "No operation specified"}
            
            # Führe die angeforderte Operation aus
            if operation == "disable_scheduled_task":
                return self.disable_scheduled_task(params.get("task_name"))
            elif operation == "enable_scheduled_task":
                return self.enable_scheduled_task(params.get("task_name"))
            elif operation == "get_scheduled_task_status":
                return self.get_scheduled_task_status(params.get("task_name"))
            elif operation == "disable_service":
                return self.disable_service(params.get("service_name"))
            elif operation == "enable_service":
                return self.enable_service(params.get("service_name"), params.get("start_type", "manual"))
            elif operation == "test_connection":
                return {"status": "success", "message": "Service is running with SYSTEM privileges"}
            else:
                return {"status": "error", "message": f"Unknown operation: {operation}"}
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            logging.error(traceback.format_exc())
            return {"status": "error", "message": str(e)}

    def disable_scheduled_task(self, task_name):
        """Deaktiviert eine geplante Aufgabe"""
        if not task_name:
            return {"status": "error", "message": "No task name specified"}
        
        logging.info(f"Disabling scheduled task: {task_name}")
        
        # Prüfe, ob die Aufgabe existiert
        status = self.get_scheduled_task_status(task_name)
        if status.get("task_status") == "Not Found":
            return {"status": "success", "message": f"Task {task_name} not found, skipping disable."}
        if status.get("task_status") == "Disabled":
            return {"status": "success", "message": f"Task {task_name} already disabled."}
        
        # Deaktiviere die Aufgabe
        cmd = f'schtasks /Change /TN "{task_name}" /Disable'
        result = self.run_command(cmd)
        
        if result["returncode"] == 0:
            return {"status": "success", "message": f"Task {task_name} disabled successfully."}
        else:
            return {
                "status": "error", 
                "message": f"Failed to disable task {task_name}.",
                "details": {
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "returncode": result["returncode"]
                }
            }

    def enable_scheduled_task(self, task_name):
        """Aktiviert eine geplante Aufgabe"""
        if not task_name:
            return {"status": "error", "message": "No task name specified"}
        
        logging.info(f"Enabling scheduled task: {task_name}")
        
        # Prüfe, ob die Aufgabe existiert
        status = self.get_scheduled_task_status(task_name)
        if status.get("task_status") == "Not Found":
            return {"status": "success", "message": f"Task {task_name} not found, skipping enable."}
        if status.get("task_status") == "Enabled":
            return {"status": "success", "message": f"Task {task_name} already enabled."}
        
        # Aktiviere die Aufgabe
        cmd = f'schtasks /Change /TN "{task_name}" /Enable'
        result = self.run_command(cmd)
        
        if result["returncode"] == 0:
            return {"status": "success", "message": f"Task {task_name} enabled successfully."}
        else:
            return {
                "status": "error", 
                "message": f"Failed to enable task {task_name}.",
                "details": {
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "returncode": result["returncode"]
                }
            }

    def get_scheduled_task_status(self, task_name):
        """Ermittelt den Status einer geplanten Aufgabe"""
        if not task_name:
            return {"status": "error", "message": "No task name specified"}
        
        logging.info(f"Getting status for scheduled task: {task_name}")
        
        # Führe schtasks-Befehl aus
        cmd = f'schtasks /Query /TN "{task_name}" /FO CSV /NH'
        result = self.run_command(cmd)
        
        if result["returncode"] == 0 and result["stdout"]:
            try:
                # Analysiere CSV-Ausgabe
                parts = result["stdout"].strip("\"").split("\",\"")
                if len(parts) >= 3:
                    status_str = parts[-1].lower()
                    if "disabled" in status_str or "deaktiviert" in status_str:
                        task_status = "Disabled"
                    elif "ready" in status_str or "bereit" in status_str:
                        task_status = "Enabled"
                    else:
                        task_status = f"Unknown ({parts[-1]})"
                    
                    return {
                        "status": "success",
                        "task_status": task_status,
                        "details": {
                            "task_name": task_name,
                            "raw_status": parts[-1]
                        }
                    }
            except Exception as e:
                logging.error(f"Error parsing task status for {task_name}: {e}")
                return {
                    "status": "error",
                    "message": f"Error parsing task status: {e}",
                    "task_status": "Unknown (Parse Error)"
                }
        
        # Prüfe auf "nicht vorhanden" oder "does not exist" Fehler
        if "does not exist" in result["stderr"].lower() or "nicht vorhanden" in result["stderr"].lower():
            return {"status": "success", "task_status": "Not Found"}
        
        return {
            "status": "error",
            "message": "Failed to get task status",
            "task_status": "Unknown",
            "details": {
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "returncode": result["returncode"]
            }
        }

    def disable_service(self, service_name):
        """Deaktiviert einen Windows-Dienst"""
        if not service_name:
            return {"status": "error", "message": "No service name specified"}
        
        logging.info(f"Disabling service: {service_name}")
        
        # Stoppe den Dienst
        stop_cmd = f'sc stop "{service_name}"'
        stop_result = self.run_command(stop_cmd)
        
        # Ignoriere bestimmte Fehlercodes beim Stoppen
        # 1062: Dienst ist nicht gestartet
        # 1060: Dienst existiert nicht
        stop_success = (stop_result["returncode"] == 0 or 
                        stop_result["returncode"] in [1062, 1060])
        
        if not stop_success:
            logging.warning(f"Failed to stop service {service_name}: {stop_result['stderr']}")
        
        # Deaktiviere den Dienst
        config_cmd = f'sc config "{service_name}" start= disabled'
        config_result = self.run_command(config_cmd)
        
        if config_result["returncode"] == 0:
            return {"status": "success", "message": f"Service {service_name} disabled successfully."}
        elif config_result["returncode"] == 1060:  # Dienst existiert nicht
            return {"status": "success", "message": f"Service {service_name} not found, skipping disable."}
        else:
            return {
                "status": "error", 
                "message": f"Failed to disable service {service_name}.",
                "details": {
                    "stdout": config_result["stdout"],
                    "stderr": config_result["stderr"],
                    "returncode": config_result["returncode"]
                }
            }

    def enable_service(self, service_name, start_type="manual"):
        """Aktiviert einen Windows-Dienst"""
        if not service_name:
            return {"status": "error", "message": "No service name specified"}
        
        # Normalisiere start_type
        if start_type.lower() in ["auto", "automatic"]:
            sc_start = "auto"
        else:
            sc_start = "demand"  # manual
        
        logging.info(f"Enabling service: {service_name} with start type: {sc_start}")
        
        # Aktiviere den Dienst
        cmd = f'sc config "{service_name}" start= {sc_start}'
        result = self.run_command(cmd)
        
        if result["returncode"] == 0:
            return {"status": "success", "message": f"Service {service_name} enabled successfully with start type {sc_start}."}
        elif result["returncode"] == 1060:  # Dienst existiert nicht
            return {"status": "success", "message": f"Service {service_name} not found, skipping enable."}
        else:
            return {
                "status": "error", 
                "message": f"Failed to enable service {service_name}.",
                "details": {
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                    "returncode": result["returncode"]
                }
            }

    def run_command(self, cmd):
        """Führt einen Shell-Befehl aus und gibt das Ergebnis zurück"""
        logging.info(f"Executing command: {cmd}")
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
            
            if process.returncode == 0:
                logging.info(f"Command succeeded: {cmd}")
                logging.debug(f"Stdout: {result['stdout']}")
            else:
                logging.warning(f"Command failed with code {process.returncode}: {cmd}")
                logging.warning(f"Stderr: {result['stderr']}")
            
            return result
        except Exception as e:
            logging.error(f"Exception executing command {cmd}: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }


if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(WindowsUpdateTweakerService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(WindowsUpdateTweakerService)
