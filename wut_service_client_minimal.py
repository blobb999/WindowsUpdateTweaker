# wut_service_client_minimal.py

import os
import sys
import subprocess
import json
import time
import pywintypes
import win32file
import win32pipe

PIPE_NAME = r"\\.\pipe\WindowsUpdateTweakerPipe"
SERVICE_NAME = "WindowsUpdateTweakerService"
SERVICE_EXECUTABLE = "wut_system_service.py"

class SystemServiceClient:
    """Client für Kommunikation per Named Pipe mit dem SYSTEM-Service."""

    def __init__(self, log_function=None):
        self.log = log_function or (lambda msg: None)
        self._ensure_service_running()

    def _run_command(self, cmd):
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="ignore"
        )
        out, err = proc.communicate()
        return {"returncode": proc.returncode, "stdout": out.strip(), "stderr": err.strip()}

    def _install_service(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        svc_path = os.path.join(script_dir, SERVICE_EXECUTABLE)
        if not os.path.exists(svc_path):
            self.log(f"Service-Skript nicht gefunden: {svc_path}")
            return False
        res = self._run_command(f'"{sys.executable}" "{svc_path}" install')
        self.log(f"Service install: rc={res['returncode']} err={res['stderr']}")
        return res["returncode"] == 0

    def _start_service(self):
        res = self._run_command(f'sc start "{SERVICE_NAME}"')
        self.log(f"Service start: rc={res['returncode']} err={res['stderr']}")
        if res["returncode"] == 0:
            time.sleep(0.5)
            return True
        return False

    def _ensure_service_running(self):
        res = self._run_command(f'sc query "{SERVICE_NAME}"')
        out = res["stdout"].lower()
        if "does not exist" in out or "existiert nicht" in out:
            self.log("Service nicht installiert, installiere …")
            if not self._install_service():
                return False
        if "running" not in out and "läuft nicht" in out or "stopped" in out:
            self.log("Service nicht gestartet, starte …")
            if not self._start_service():
                return False
        return True

    def send_request(self, operation, params=None, max_retries=2):
        """Sendet eine JSON-Anfrage an den Dienst und gibt die Antwort zurück."""
        if params is None:
            params = {}
        if not self._ensure_service_running():
            return {"status": "error", "message": "Service not running"}
        request = json.dumps({"operation": operation, "params": params}).encode("utf-8")

        retries = 0
        while retries <= max_retries:
            try:
                handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
                self.log(f"Sending request: {operation} {params}")
                win32file.WriteFile(handle, request)

                # Lese Antwort
                resp_code, data = win32file.ReadFile(handle, 4096)
                win32file.CloseHandle(handle)
                response = json.loads(data.decode("utf-8"))
                self.log(f"Received response: {response}")
                return response

            except pywintypes.error as e:
                self.log(f"Pipe error ({retries}/{max_retries}): {e}")
                try: win32file.CloseHandle(handle)
                except: pass
                self._ensure_service_running()
                time.sleep(1)
                retries += 1

        return {"status": "error", "message": "Max retries reached"}

    # Convenience-Methoden
    def enable_scheduled_task(self, task_name):
        return self.send_request("enable_scheduled_task", {"task_name": task_name})

    def disable_scheduled_task(self, task_name):
        return self.send_request("disable_scheduled_task", {"task_name": task_name})

    def get_scheduled_task_status(self, task_name):
        return self.send_request("get_scheduled_task_status", {"task_name": task_name})

    def enable_service(self, service_name, start_type="manual"):
        return self.send_request("enable_service", {"service_name": service_name, "start_type": start_type})

    def disable_service(self, service_name):
        return self.send_request("disable_service", {"service_name": service_name})
