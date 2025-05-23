#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import winreg
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, font, scrolledtext
import datetime
import socket
import webbrowser
import json
from urllib import request as url_request
import threading
import time
import csv
from wut_service_client_minimal import SystemServiceClient

# --- Application Constants ---
APP_VERSION = "2.0" # User requested version 2.0
GITHUB_REPO_URL = "https://api.github.com/repos/blobb999/WindowsUpdateTweaker/releases/latest"
GITHUB_RELEASES_PAGE_URL = "https://github.com/blobb999/WindowsUpdateTweaker/releases"

# --- Color Constants for Status ---
COLOR_ACTIVE = "green"
COLOR_INACTIVE = "red"
COLOR_NEUTRAL = "black" # Default text color
COLOR_ERROR = "orange"

# --- Logging Setup ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]) if hasattr(sys, "argv") and sys.argv else ".")
LOG_FILE = os.path.join(SCRIPT_DIR, "tweak_log.txt")

def log_message(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception as e:
        print(f"Logging failed: {e}", file=sys.stderr)

log_message("--- Script started ---")

IS_WINDOWS = os.name == "nt"
system_client = SystemServiceClient(log_message)
system_client.ensure_service_running()


if not IS_WINDOWS:
    log_message("Warning: This script is intended for Windows. GUI will load, but functions will likely fail.")

ADMINISTRATORS_SID = "*S-1-5-32-544"
EVERYONE_SID       = "*S-1-1-0"

# ---------------------------
# Helper: run shell commands
# ---------------------------
def run_cmd(cmd, log_output=True):
    log_message(f"Executing: {cmd}")
    result = {"success": False, "stdout": "", "stderr": "", "returncode": -1}
    if not IS_WINDOWS: result["stderr"] = "Not on Windows, command not executed."; log_message(result["stderr"]); return result
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, startupinfo=si, encoding="utf-8", errors="ignore")
        result["stdout"] = proc.stdout.strip()
        result["stderr"] = proc.stderr.strip()
        result["returncode"] = proc.returncode
        if proc.returncode == 0:
            result["success"] = True
            if log_output: log_message(f"Success: {cmd}\nStdout: {result['stdout']}\nStderr: {result['stderr']}")
        else:
            if log_output: log_message(f"Command non-zero exit: {cmd}\nReturn Code: {proc.returncode}\nStdout: {result['stdout']}\nStderr: {result['stderr']}")
    except Exception as ex: 
        result["stderr"] = str(ex)
        log_message(f"Exception in run_cmd(\"{cmd}\"): {ex}")
    return result

# ---------------------------
# Paths & constants
# ---------------------------
HOSTS_PATH       = r"C:\Windows\System32\drivers\etc\hosts"
WUAUCLT_PATH     = r"C:\Windows\System32\wuauclt.exe"
WUAUCLT_BAK_PATH = WUAUCLT_PATH + ".bak"
USOCLIENT_PATH   = r"C:\Windows\System32\UsoClient.exe"
USOCLIENT_BAK_PATH = USOCLIENT_PATH + ".bak"
SEDSVC_PATH      = r"C:\Windows\System32\sedsvc.exe"
SEDSVC_BAK_PATH  = SEDSVC_PATH + ".bak"

REG_AU_PATH = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
REG_WINDOWSUPDATE_PATH = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
REG_CLOUDCONTENT_PATH = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent"

FW_RULE_NAME = "Block Windows Update & Telemetry (WUTT)"
FW_HOSTNAMES_TO_BLOCK = list(set([
    "windowsupdate.microsoft.com", "update.microsoft.com", "download.windowsupdate.com",
    "delivery.mp.microsoft.com", "sls.update.microsoft.com", "fe2.update.microsoft.com",
    "displaycatalog.mp.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com", 
    "v10.events.data.microsoft.com", "settings-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com", "vortex.data.microsoft.com"
]))

HOSTS_ENTRIES_TO_BLOCK = list(set([
    "127.0.0.1 windowsupdate.microsoft.com", "127.0.0.1 update.microsoft.com",
    "127.0.0.1 download.windowsupdate.com", "127.0.0.1 delivery.mp.microsoft.com",
    "127.0.0.1 sls.update.microsoft.com", "127.0.0.1 fe2.update.microsoft.com",
    "127.0.0.1 displaycatalog.mp.microsoft.com", "127.0.0.1 tsfe.trafficshaping.dsp.mp.microsoft.com",
    "127.0.0.1 v10.events.data.microsoft.com", "127.0.0.1 settings-win.data.microsoft.com",
    "127.0.0.1 telecommand.telemetry.microsoft.com", "127.0.0.1 vortex.data.microsoft.com"
]))

STARTUP_TASK_NAME = "WindowsUpdateTweakerAutorun"

SCHEDULED_TASKS_TO_MANAGE = [
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan", r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work", r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistant", r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun",
    r"\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun", r"\Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval",
    r"\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateDelay", r"\Microsoft\Windows\UpdateOrchestrator\Policy Install",
    r"\Microsoft\Windows\UpdateOrchestrator\Refresh Settings", r"\Microsoft\Windows\UpdateOrchestrator\Report policies",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Retry Scan",
    r"\Microsoft\Windows\WindowsUpdate\Automatic App Update", r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    r"\Microsoft\Windows\WindowsUpdate\sih", r"\Microsoft\Windows\WindowsUpdate\sihboot"
]

OPTIONAL_TELEMETRY_SERVICES = {
    "WpnUserService": ("Windows Push Notifications User Service (WpnUserService_XXXXX)", "Optional: Disables Windows Push Notifications User Service. Name varies."),
    "Mcx2Svc": ("Microsoft Compatibility Appraiser (Mcx2Svc)", "Optional: Disables Microsoft Compatibility Appraiser service.")
}


# ----------------------------------------
# Registry-Hacks für geschützte Dienste
# ----------------------------------------

def _registry_disable(name, silent=False):
    """
    Setzt den Start-Wert eines Dienstes in der Registry auf 4 (Disabled).
    Liefert True bei Erfolg, False sonst.
    """
    import winreg
    try:
        key_path = fr"SYSTEM\CurrentControlSet\Services\{name}"
        success = set_registry_value(
            key_path,
            "Start",
            4,
            value_type=winreg.REG_DWORD,
            silent=silent
        )
        log_message(f"Registry disable for {name}: {success}")
        return success
    except PermissionError:
        log_message(f"Permission denied writing registry for disabling {name}")
        if not silent:
            from tkinter import messagebox
            messagebox.showerror(
                "Zugriff verweigert",
                f"Der Dienst '{name}' ist geschützt und konnte nicht per Registry deaktiviert werden.\n"
                "Bitte führe das Programm als Administrator aus oder passe die Berechtigungen manuell an.",
                parent=globals().get("root", None)
            )
        return False


def _registry_enable(name, start_type="demand", silent=False):
    """
    Setzt den Start-Wert eines Dienstes in der Registry auf:
      2 = Automatic (auto) oder
      3 = Manual (demand).
    Liefert True bei Erfolg, False sonst.
    """
    import winreg
    sc_start = 'auto' if start_type.lower() in ('auto', 'automatic') else 'demand'
    start_val = 2 if sc_start == 'auto' else 3
    try:
        key_path = fr"SYSTEM\CurrentControlSet\Services\{name}"
        success = set_registry_value(
            key_path,
            "Start",
            start_val,
            value_type=winreg.REG_DWORD,
            silent=silent
        )
        log_message(f"Registry enable for {name}: set Start={start_val} -> {success}")
        return success
    except PermissionError:
        log_message(f"Permission denied writing registry for enabling {name}")
        if not silent:
            from tkinter import messagebox
            messagebox.showerror(
                "Zugriff verweigert",
                f"Der Dienst '{name}' ist geschützt und konnte nicht per Registry aktiviert werden.\n"
                "Bitte führe das Programm als Administrator aus oder passe die Berechtigungen manuell an.",
                parent=globals().get("root", None)
            )
        return False


# ---------------------------
# Service Management
# ---------------------------
def get_service_status(name):
    log_message(f"Getting service status for {name}")
    if not IS_WINDOWS: return "Unknown (Not Windows)"
    if not name or "NonExistent" in name: return "Missing (Invalid Name)"
    try:
        cmd_result = run_cmd(f"sc query \"{name}\"", log_output=False)
        if cmd_result["success"]:
            state = "Unknown"; start_type = "Unknown"
            for l in cmd_result["stdout"].splitlines():
                if "STATE" in l: state_parts = l.split(); state = state_parts[3] if len(state_parts) > 3 else "Unknown"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Services\\{name}") as key:
                start_val = winreg.QueryValueEx(key, "Start")[0]
                if start_val == 2: start_type = "Automatic"
                elif start_val == 3: start_type = "Manual"
                elif start_val == 4: start_type = "Disabled"
            
            if state == "RUNNING": return "Running"
            if start_type == "Disabled": return "Disabled"
            if state == "STOPPED": return "Stopped"
            return f"{state} ({start_type})"
        else:
            if "does not exist" in cmd_result["stderr"].lower() or "nicht vorhanden" in cmd_result["stderr"].lower(): return "Missing"
            return "Unknown"
    except FileNotFoundError:
        log_message(f"Service key for {name} not found in registry.")
        return "Missing"
    except Exception as e: log_message(f"Exception getting service status for {name}: {e}"); return "Unknown"


def disable_service(name, silent=False):
    """
    Deaktiviert einen Windows-Dienst:
    - Für protected Dienste via Registry (_registry_disable)
    - Sonst via sc config, mit SYSTEM-Fallback.
    """
    import ctypes
    from tkinter import messagebox

    if not IS_WINDOWS:
        log_message(f"Cannot disable service {name}: Not Windows")
        return False

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False

    log_message(f"Disabling service: {name}")

    protected = ("WaaSMedicSvc", "DoSvc")
    if name in protected:
        if is_admin:
            return _registry_disable(name, silent)
        else:
            log_message(f"No admin rights: SYSTEM-Fallback registry-disable {name}")
            return system_client.disable_service(name)

    svc = name.split("_",1)[0] if name.startswith("WpnUserService_") else name
    cmd = f'sc config "{svc}" start= disabled'
    res = run_cmd(cmd, log_output=True)
    rc = res.get("returncode",-1)
    stderr = res.get("stderr","")

    if res["success"]:
        log_message(f"{svc} disabled via sc config")
        # Dienst jetzt auch sofort anhalten
        stop_res = run_cmd(f'sc stop "{svc}"', log_output=True)
        if stop_res.get("success"):
            log_message(f"{svc} stopped via sc stop")
        else:
            log_message(f"{svc} konnte nicht gestoppt werden: {stop_res.get('stderr')}")
        return True

    if rc == 5 or (rc == 1 and "zugriff verweigert" in stderr.lower()):
        log_message(f"Access denied for {svc}, SYSTEM-Fallback sc config")
        return system_client.disable_service(svc)

    if not silent:
        messagebox.showerror(
            "Fehler beim Deaktivieren des Dienstes",
            f"Fehler beim Deaktivieren von '{svc}' (Code {rc}):\n{stderr}",
            parent=globals().get("root", None)
        )
    return False


def enable_service(name, start_type="demand", silent=False):
    """
    Aktiviert einen Windows-Dienst:
    - Für protected Dienste via Registry (_registry_enable)
    - Sonst via sc config, mit SYSTEM-Fallback.
    """
    import ctypes
    from tkinter import messagebox

    if not IS_WINDOWS:
        log_message(f"Cannot enable service {name}: Not Windows")
        return False

    # Admin?
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False

    log_message(f"Enabling service: {name} -> {start_type}")

    protected = ("WaaSMedicSvc", "DoSvc")
    if name in protected:
        # Registry-Hack
        if is_admin:
            return _registry_enable(name, start_type, silent)
        else:
            log_message(f"No admin rights: SYSTEM-Fallback registry-enable {name}")
            return system_client.enable_service(name, start_type)

    # Standard-Fall: sc config
    svc = name.split("_",1)[0] if name.startswith("WpnUserService_") else name
    sc_start = 'auto' if start_type.lower().startswith("a") else 'demand'
    cmd = f'sc config "{svc}" start= {sc_start}'
    res = run_cmd(cmd, log_output=True)
    rc  = res.get("returncode", -1)
    stderr = res.get("stderr","")

    if res["success"]:
        log_message(f"{svc} set to start={sc_start}")
        return True

    # Zugriffsfehler → SYSTEM-Fallback
    if rc == 5 or (rc == 1 and "zugriff verweigert" in stderr.lower()):
        log_message(f"Access denied for {svc}, SYSTEM-Fallback sc config")
        return system_client.enable_service(svc, start_type)

    # Anderer Fehler
    if not silent:
        messagebox.showerror(
            "Fehler beim Aktivieren des Dienstes",
            f"Fehler beim Aktivieren von '{svc}' (Code {rc}):\n{stderr}",
            parent=globals().get("root", None)
        )
    return False

# ---------------------------------------
# Scheduled Task Management
# ---------------------------------------
def get_scheduled_task_status(task_name):
    log_message(f"Getting status for scheduled task: {task_name}")

    if not IS_WINDOWS:
        return "Unknown (Not Windows)"

    # 1) Native Abfrage
    res = run_cmd(f'schtasks /Query /TN "{task_name}" /FO CSV /NH', log_output=False)
    rc = res.get("returncode", -1)
    out = res.get("stdout", "").strip()
    err = res.get("stderr", "")

    if rc == 0 and out:
        # robustes CSV-Parsing
        import csv
        try:
            line = out.splitlines()[0]
            fields = next(csv.reader([line], skipinitialspace=True))
            status_field = fields[-1].strip().strip('"').lower()
            if status_field in ("ready", "bereit", "enabled"):
                return "Enabled"
            if "disabled" in status_field or "deaktiviert" in status_field:
                return "Disabled"
            return f"Unknown ({fields[-1]})"
        except Exception as e:
            log_message(f"Parse error for task status: {e}")
            return "Unknown (Parse Error)"

    # 2) SYSTEM-Fallback bei Zugriff verweigert
    if rc == 1 and "zugriff verweigert" in err.lower():
        log_message(f"Access denied for {task_name}, SYSTEM-Fallback …")
        resp = system_client.get_scheduled_task_status(task_name)
        if isinstance(resp, dict) and resp.get("status") == "success":
            return resp.get("task_status", "Unknown")
        return "Unknown"

    # 3) Nicht existierend
    if "kann die angegebene datei nicht finden" in err.lower() or "cannot find" in err.lower():
        return "Not Found"

    return "Unknown"


def enable_scheduled_task(task_name, silent=False):
    log_message(f"Enabling scheduled task: {task_name}")

    # 1) Native Versuch
    res = run_cmd(f'schtasks /Change /TN "{task_name}" /Enable', log_output=not silent)
    rc = res.get("returncode", -1)
    if res["success"]:
        return True

    # 2) SYSTEM-Fallback bei Zugriff verweigert
    stderr = res.get("stderr", "")
    if rc == 1 and "zugriff verweigert" in stderr.lower():
        log_message(f"Access denied for {task_name}, SYSTEM-Fallback …")
        resp = system_client.enable_scheduled_task(task_name)
        return isinstance(resp, dict) and resp.get("status") == "success"

    # 3) Anderer Fehler
    if not silent:
        from tkinter import messagebox
        messagebox.showerror(
            "Fehler",
            f"Fehler beim Aktivieren der Aufgabe '{task_name}':\n{stderr}",
            parent=globals().get("root", None)
        )
    return False


def disable_scheduled_task(task_name, silent=False):
    log_message(f"Disabling scheduled task: {task_name}")

    # 1) Native Versuch
    res = run_cmd(f'schtasks /Change /TN "{task_name}" /Disable', log_output=not silent)
    rc = res.get("returncode", -1)
    if res["success"]:
        return True

    # 2) SYSTEM-Fallback bei Zugriff verweigert
    stderr = res.get("stderr", "")
    if rc == 1 and "zugriff verweigert" in stderr.lower():
        log_message(f"Access denied for {task_name}, SYSTEM-Fallback …")
        resp = system_client.disable_scheduled_task(task_name)
        return isinstance(resp, dict) and resp.get("status") == "success"

    # 3) Anderer Fehler
    if not silent:
        from tkinter import messagebox
        messagebox.showerror(
            "Fehler",
            f"Fehler beim Deaktivieren der Aufgabe '{task_name}':\n{stderr}",
            parent=globals().get("root", None)
        )
    return False



# ---------------------------
# Registry Management
# ---------------------------
def set_registry_value(key_path, value_name, value_data, value_type=None, root_key=winreg.HKEY_LOCAL_MACHINE, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Setting registry value: {key_path}\\{value_name} = {value_data}")
    try:
        # Determine value type if not specified
        if value_type is None:
            if isinstance(value_data, int): value_type = winreg.REG_DWORD
            elif isinstance(value_data, str): value_type = winreg.REG_SZ
            else: value_type = winreg.REG_BINARY
        
        # Create key if it doesn't exist
        try: key = winreg.CreateKeyEx(root_key, key_path, 0, winreg.KEY_WRITE)
        except Exception as e: 
            log_message(f"Error creating registry key {key_path}: {e}")
            if not silent: messagebox.showerror("Registry Error", f"Error creating registry key {key_path}: {e}", parent=globals().get('root', None))
            return False
        
        # Set value
        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        winreg.CloseKey(key)
        log_message(f"Registry value set successfully: {key_path}\\{value_name} = {value_data}")
        return True
    except Exception as e:
        log_message(f"Error setting registry value {key_path}\\{value_name}: {e}")
        if not silent: messagebox.showerror("Registry Error", f"Error setting registry value {key_path}\\{value_name}: {e}", parent=globals().get('root', None))
        return False

def delete_registry_value(key_path, value_name, root_key=winreg.HKEY_LOCAL_MACHINE, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Deleting registry value: {key_path}\\{value_name}")
    try:
        key = winreg.OpenKey(root_key, key_path, 0, winreg.KEY_WRITE)
        try: winreg.DeleteValue(key, value_name)
        except FileNotFoundError: log_message(f"Registry value {key_path}\\{value_name} not found, already deleted.")
        winreg.CloseKey(key)
        log_message(f"Registry value deleted successfully: {key_path}\\{value_name}")
        return True
    except FileNotFoundError:
        log_message(f"Registry key {key_path} not found, nothing to delete.")
        return True
    except Exception as e:
        log_message(f"Error deleting registry value {key_path}\\{value_name}: {e}")
        if not silent: messagebox.showerror("Registry Error", f"Error deleting registry value {key_path}\\{value_name}: {e}", parent=globals().get('root', None))
        return False

def get_registry_value(key_path, value_name, default=None, root_key=winreg.HKEY_LOCAL_MACHINE):
    if not IS_WINDOWS: return default
    try:
        key = winreg.OpenKey(root_key, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return value
    except (FileNotFoundError, WindowsError):
        return default

def get_reg_tweak_status(key_path, value_name, expected_val_for_disabled, default_is_disabled=True, val_if_not_set_is_disabled=True):
    if not IS_WINDOWS: return "Unknown (Not Windows)"
    val = get_registry_value(key_path, value_name)
    if val is None:
        return "Disabled" if (default_is_disabled or val_if_not_set_is_disabled) else "Enabled"
    return "Disabled" if val == expected_val_for_disabled else "Enabled"

# Specific Registry Tweaks
def apply_no_auto_update(silent=False): return set_registry_value(REG_AU_PATH, "NoAutoUpdate", 1, silent=silent)
def undo_no_auto_update(silent=False): return set_registry_value(REG_AU_PATH, "NoAutoUpdate", 0, silent=silent)
def get_no_auto_update_status(): return get_reg_tweak_status(REG_AU_PATH, "NoAutoUpdate", 1, val_if_not_set_is_disabled=False) # Default is 0 (auto update on), so if not set, tweak is NOT applied

def apply_auoptions_notify(silent=False): return set_registry_value(REG_AU_PATH, "AUOptions", 1, silent=silent)
def undo_auoptions_notify(silent=False): return set_registry_value(REG_AU_PATH, "AUOptions", 4, silent=silent) # Default is often 4 (auto download and schedule install)
def get_auoptions_status(): return get_reg_tweak_status(REG_AU_PATH, "AUOptions", 1)

def apply_usewuserver_disable(silent=False): return set_registry_value(REG_AU_PATH, "UseWUServer", 0, silent=silent)
def undo_usewuserver_disable(silent=False): return set_registry_value(REG_AU_PATH, "UseWUServer", 1, silent=silent) # Assuming undo means enable WSUS
def get_usewuserver_status(): return get_reg_tweak_status(REG_AU_PATH, "UseWUServer", 0)

def apply_disable_consumer_features(silent=False): return set_registry_value(REG_CLOUDCONTENT_PATH, "DisableWindowsConsumerFeatures", 1, silent=silent)
def undo_disable_consumer_features(silent=False): return set_registry_value(REG_CLOUDCONTENT_PATH, "DisableWindowsConsumerFeatures", 0, silent=silent)
def get_disable_consumer_features_status(): return get_reg_tweak_status(REG_CLOUDCONTENT_PATH, "DisableWindowsConsumerFeatures", 1)

# ---------------------------
# Hosts File Management
# ---------------------------
def get_hosts_status():
    if not IS_WINDOWS: return "Unknown (Not Windows)"
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8") as f: content = f.read()
        return "Blocked" if all(entry in content for entry in HOSTS_ENTRIES_TO_BLOCK) else "Not Blocked"
    except Exception as e: log_message(f"Error reading hosts file: {e}"); return "Unknown"

def apply_hosts_block(silent=False):
    if not IS_WINDOWS: return False
    log_message("Applying hosts block.")
    try:
        with open(HOSTS_PATH, "r+", encoding="utf-8") as f:
            content_lines = f.readlines()
            f.seek(0)
            # Write existing lines not part of our block list first
            for line in content_lines:
                if line.strip() not in HOSTS_ENTRIES_TO_BLOCK:
                    f.write(line)
            # Add our block entries if not already present (implicitly handled by not writing them above if they were there)
            for entry in HOSTS_ENTRIES_TO_BLOCK:
                if entry + "\n" not in content_lines and entry not in content_lines: # check with and without newline
                    f.write(entry + "\n")
            f.truncate()
        log_message("Hosts block applied."); return True
    except Exception as e: log_message(f"Error applying hosts block: {e}"); return False

def undo_hosts_block(silent=False):
    if not IS_WINDOWS: return False
    log_message("Undoing hosts block.")
    try:
        with open(HOSTS_PATH, "r+", encoding="utf-8") as f:
            lines = f.readlines()
            f.seek(0)
            for line in lines:
                if line.strip() not in HOSTS_ENTRIES_TO_BLOCK:
                    f.write(line)
            f.truncate()
        log_message("Hosts block undone."); return True
    except Exception as e: log_message(f"Error undoing hosts block: {e}"); return False

# ---------------------------
# Firewall Management
# ---------------------------
def get_fw_status():
    if not IS_WINDOWS: return "Unknown (Not Windows)"
    res = run_cmd(f"netsh advfirewall firewall show rule name=\"{FW_RULE_NAME}\"", log_output=False)
    return "Blocked" if res["success"] and ("Ok." in res["stdout"] or "OK." in res["stdout"]) else "Not Blocked"

def apply_fw_block(silent=False):
    if not IS_WINDOWS: return False
    log_message("Applying firewall block.")
    if get_fw_status() == "Blocked": log_message("Firewall rule already exists."); return True
    
    resolved_ips = set()
    for hostname in FW_HOSTNAMES_TO_BLOCK:
        try: 
            # Get all IPs for a hostname
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                if item[4][0] not in resolved_ips: # Avoid duplicates
                    resolved_ips.add(item[4][0])
                    log_message(f"Resolved {hostname} to {item[4][0]}")
        except socket.gaierror: log_message(f"Could not resolve {hostname}")
    
    if not resolved_ips: log_message("No IPs resolved, cannot create firewall rule."); return False
    ips_csv = ",".join(resolved_ips)
    cmd = f"netsh advfirewall firewall add rule name=\"{FW_RULE_NAME}\" dir=out action=block remoteip={ips_csv} enable=yes"
    return run_cmd(cmd, log_output=not silent)["success"]

def undo_fw_block(silent=False):
    if not IS_WINDOWS: return False
    log_message("Undoing firewall block.")
    if get_fw_status() == "Not Blocked": log_message("Firewall rule does not exist."); return True
    return run_cmd(f"netsh advfirewall firewall delete rule name=\"{FW_RULE_NAME}\"", log_output=not silent)["success"]

# ---------------------------
# Startup Task Management
# ---------------------------
SELF_SCRIPT_PATH = os.path.abspath(sys.argv[0]) if hasattr(sys, "argv") and sys.argv else "WindowsUpdateTweaker.py"
def get_startup_task_status():
    """
    Prüft, ob der Autorun-Task existiert und ob er Enabled/Disabled ist.
    Nutzt CSV-Ausgabe und wertet das dritte Feld ("Status") aus.
    """
    if not IS_WINDOWS:
        return "Unknown (Not Windows)"
    # Query im CSV-Format: "TaskName","Next Run Time","Status"
    res = run_cmd(
        f'schtasks /Query /TN "{STARTUP_TASK_NAME}" /FO CSV /NH',
        log_output=False
    )
    if res["success"] and res.get("stdout"):
        # Beispiel stdout: "\"WindowsUpdateTweakerAutorun\",\"N/A\",\"Disabled\""
        parts = [p.strip().strip('"') for p in res["stdout"].split(",")]
        status = parts[2] if len(parts) >= 3 else "Unknown"
        if status.lower() == "ready" or status.lower() == "bereit":    # engl. Default für "Bereit"
            return "Enabled"
        if status.lower() == "disabled" or status.lower() == "deaktiviert":
            return "Disabled"
        return status  # z.B. "Running" oder andere Werte
    # Wenn Task nicht gefunden oder Fehler
    return "Not Created"


def create_startup_task(silent=False):
    if not IS_WINDOWS: return False
    log_message("Creating startup task.")
    cmd = f"schtasks /Create /TN \"{STARTUP_TASK_NAME}\" /TR \"\"{sys.executable}\" \\\"{SELF_SCRIPT_PATH}\\\" --autorun-silent\" /SC ONLOGON /RL HIGHEST /F"
    return run_cmd(cmd, log_output=not silent)["success"]

def delete_startup_task(silent=False):
    if not IS_WINDOWS: return False
    log_message("Deleting startup task.")
    return run_cmd(f"schtasks /Delete /TN \"{STARTUP_TASK_NAME}\" /F", log_output=not silent)["success"]

# ---------------------------
# Admin Rights Check
# ---------------------------
def is_admin(ctypes_module):
    if not IS_WINDOWS: return False # Assume not admin if not on Windows
    if ctypes_module:
        try: return ctypes_module.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e: log_message(f"Admin check failed: {e}"); return False
    return False # Fallback if ctypes is not available

# ---------------------------
# Dynamic Service Name Discovery (for WpnUserService)
# ---------------------------
def find_wpnuserservice_name():
    if not IS_WINDOWS: return None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                if subkey_name.startswith("WpnUserService_"):
                    winreg.CloseKey(key)
                    log_message(f"Found WpnUserService: {subkey_name}")
                    return subkey_name
                i += 1
            except OSError: # No more subkeys
                break
        winreg.CloseKey(key)
    except Exception as e:
        log_message(f"Error finding WpnUserService: {e}")
    log_message("WpnUserService not found with specific suffix.")
    return "WpnUserService_NonExistent" # Placeholder if not found

# --- Helper functions for tweak status display ---
def is_tweak_active(status, tweak_name=None):
    """Determine if a tweak is active based on its status string and optionally the tweak name."""
    active_statuses = ["Disabled", "Blocked", "Renamed", "Locked"]
    
    # Spezialfall für den Autostart-Tweak
    if tweak_name and "Autostart" in tweak_name and status == "Enabled":
        return True
        
    return status in active_statuses

def get_status_color(status, tweak_name=None):
    """Return the appropriate color for a status string."""
    if is_tweak_active(status, tweak_name):
        return COLOR_ACTIVE
    elif status in ["Enabled", "Not Blocked", "Writable"]:
        return COLOR_INACTIVE
    elif status in ["Missing", "Not Found", "Unknown", "Not Created"]:
        return COLOR_ERROR
    return COLOR_NEUTRAL

def get_status_display_text(status, tweak_name=None):
    """Convert status to a user-friendly display text."""
    # Spezialfall für den Autostart-Tweak
    if tweak_name and "Autostart" in tweak_name:
        if status == "Enabled":
            return "Enabled ✓"
        elif status == "Disabled":
            return "Disabled ✗"
        elif status == "Not Created":
            return "Not Created ✗"
    
    if status == "Disabled":
        return "Disabled ✓"
    elif status == "Enabled":
        return "Enabled ✗"
    elif status == "Blocked":
        return "Blocked ✓"
    elif status == "Not Blocked":
        return "Not Blocked ✗"
    elif status == "Renamed":
        return "Renamed ✓"
    elif status == "Writable":
        return "Writable ✗"
    elif status == "Locked":
        return "Locked ✓"
    elif status == "Not Created":
        return "Not Created ✗"
    return status

# ---------------------------
# File Management
# ---------------------------
def get_generic_file_status(file_path, backup_path, file_name):
    if not IS_WINDOWS: return "Unknown (Not Windows)"
    if not os.path.exists(file_path) and os.path.exists(backup_path): return "Renamed"
    if not os.path.exists(file_path): return "Missing"
    
    # Check if file is locked (ACL)
    result = run_cmd(f"icacls \"{file_path}\"", log_output=False)
    if result["success"]:
        # Check for DENY permission for Everyone or Jeder (German)
        if f"{EVERYONE_SID}:(DENY)(W)" in result["stdout"] or "Jeder:(DENY)(W)" in result["stdout"] or "Everyone:(DENY)(W)" in result["stdout"]:
            return "Locked"
    return "Writable"

def apply_generic_file_lock(file_path, backup_path, file_name, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Applying lock to {file_name}.")
    
    # Check if file exists
    if not os.path.exists(file_path):
        log_message(f"File {file_name} not found at {file_path}.")
        if not silent: messagebox.showerror("File Not Found", f"File {file_name} not found at {file_path}.", parent=globals().get('root', None))
        return False
    
    # Check if file is already renamed
    if os.path.exists(backup_path):
        log_message(f"Cannot lock {file_name} because it is already renamed.")
        if not silent: messagebox.showerror("File Already Renamed", f"Cannot lock {file_name} because it is already renamed. Please restore the file first.", parent=globals().get('root', None))
        return False
    
    # Check if file is already locked
    status = get_generic_file_status(file_path, backup_path, file_name)
    if status == "Locked":
        log_message(f"File {file_name} is already locked.")
        return True
    
    # Take ownership and grant full control to Administrators
    log_message(f"Taking ownership of {file_name} and granting full control to Administrators.")
    run_cmd(f"takeown /F \"{file_path}\" /A", log_output=True)
    run_cmd(f"icacls \"{file_path}\" /grant {ADMINISTRATORS_SID}:F", log_output=True)
    
    # Deny write access to Everyone
    log_message(f"Denying write access to Everyone for {file_name}.")
    result = run_cmd(f"icacls \"{file_path}\" /deny {EVERYONE_SID}:(W)", log_output=True)
    
    # Verify lock was applied
    if result["success"]:
        log_message(f"Lock applied to {file_name}.")
        return True
    else:
        log_message(f"Failed to apply lock to {file_name}.")
        if not silent: messagebox.showerror("Lock Failed", f"Failed to apply lock to {file_name}. Error: {result['stderr']}", parent=globals().get('root', None))
        return False

def undo_generic_file_lock(file_path, backup_path, file_name, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Removing lock from {file_name}.")
    
    # Check if file exists
    if not os.path.exists(file_path):
        log_message(f"File {file_name} not found at {file_path}.")
        if not silent: messagebox.showerror("File Not Found", f"File {file_name} not found at {file_path}.", parent=globals().get('root', None))
        return False
    
    # Check if file is already renamed
    if os.path.exists(backup_path):
        log_message(f"Cannot unlock {file_name} because it is renamed.")
        if not silent: messagebox.showerror("File Renamed", f"Cannot unlock {file_name} because it is renamed. Please restore the file first.", parent=globals().get('root', None))
        return False
    
    # Check if file is already unlocked
    status = get_generic_file_status(file_path, backup_path, file_name)
    if status == "Writable":
        log_message(f"File {file_name} is already unlocked.")
        return True
    
    # Remove deny rule for Everyone
    log_message(f"Removing deny rule for Everyone from {file_name}.")
    result = run_cmd(f"icacls \"{file_path}\" /remove:d {EVERYONE_SID}", log_output=True)
    
    # Restore ownership to TrustedInstaller
    log_message(f"Restoring ownership of {file_name} to TrustedInstaller.")
    run_cmd(f"icacls \"{file_path}\" /setowner \"NT SERVICE\\TrustedInstaller\" /T /C /L /Q", log_output=True)
    
    # Verify lock was removed
    if result["success"]:
        log_message(f"Lock removed from {file_name}.")
        return True
    else:
        log_message(f"Failed to remove lock from {file_name}.")
        if not silent: messagebox.showerror("Unlock Failed", f"Failed to remove lock from {file_name}. Error: {result['stderr']}", parent=globals().get('root', None))
        return False

def apply_generic_file_rename(file_path, backup_path, file_name, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Renaming {file_name}.")
    
    # Check if file exists
    if not os.path.exists(file_path):
        log_message(f"File {file_name} not found at {file_path}.")
        if not silent: messagebox.showerror("File Not Found", f"File {file_name} not found at {file_path}.", parent=globals().get('root', None))
        return False
    
    # Check if file is already renamed
    if os.path.exists(backup_path):
        log_message(f"File {file_name} is already renamed.")
        return True
    
    # Check if file is locked
    status = get_generic_file_status(file_path, backup_path, file_name)
    if status == "Locked":
        log_message(f"Cannot rename {file_name} because it is locked.")
        if not silent: messagebox.showerror("File Locked", f"Cannot rename {file_name} because it is locked. Please unlock the file first.", parent=globals().get('root', None))
        return False
    
    # Take ownership and grant full control to Administrators
    log_message(f"Taking ownership of {file_name} and granting full control to Administrators.")
    run_cmd(f"takeown /F \"{file_path}\" /A", log_output=True)
    run_cmd(f"icacls \"{file_path}\" /grant {ADMINISTRATORS_SID}:F", log_output=True)
    
    # Rename file
    try:
        shutil.move(file_path, backup_path)
        log_message(f"File {file_name} renamed to {os.path.basename(backup_path)}.")
        return True
    except Exception as e:
        log_message(f"Failed to rename {file_name}. Error: {e}")
        if not silent: messagebox.showerror("Rename Failed", f"Failed to rename {file_name}. Error: {e}", parent=globals().get('root', None))
        return False

def undo_generic_file_rename(file_path, backup_path, file_name, silent=False):
    if not IS_WINDOWS: return False
    log_message(f"Restoring {file_name}.")
    
    # Check if backup file exists
    if not os.path.exists(backup_path):
        log_message(f"Backup file for {file_name} not found at {backup_path}.")
        if not silent: messagebox.showerror("Backup Not Found", f"Backup file for {file_name} not found at {backup_path}.", parent=globals().get('root', None))
        return False
    
    # Check if original file already exists
    if os.path.exists(file_path):
        log_message(f"Original file {file_name} already exists at {file_path}.")
        return True
    
    # Rename file back
    try:
        shutil.move(backup_path, file_path)
        log_message(f"File {os.path.basename(backup_path)} restored to {file_name}.")
        
        # Restore ownership to TrustedInstaller
        log_message(f"Restoring ownership of {file_name} to TrustedInstaller.")
        run_cmd(f"icacls \"{file_path}\" /setowner \"NT SERVICE\\TrustedInstaller\" /T /C /L /Q", log_output=True)
        
        return True
    except Exception as e:
        log_message(f"Failed to restore {file_name}. Error: {e}")
        if not silent: messagebox.showerror("Restore Failed", f"Failed to restore {file_name}. Error: {e}", parent=globals().get('root', None))
        return False

# ---------------------------
# GUI Class
# ---------------------------
class WindowsUpdateTweakerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title(f"Windows Update Tweaker v{APP_VERSION}")
        self.master.geometry("800x600")
        self.master.minsize(800, 700)
        
        # Set up styles
        self.setup_styles()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.master, style="Main.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create header
        self.create_header()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create content frames for each tab
        self.content_frame_coreservices = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_updateclients = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_scheduledtasks = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_registrysettings = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_network = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_telemetry = ttk.Frame(self.notebook, style="Content.TFrame")
        self.content_frame_autostart = ttk.Frame(self.notebook, style="Content.TFrame")
        
        # Add tabs to notebook
        self.notebook.add(self.content_frame_coreservices, text="Core Services")
        self.notebook.add(self.content_frame_updateclients, text="Update Clients")
        self.notebook.add(self.content_frame_scheduledtasks, text="Scheduled Tasks")
        self.notebook.add(self.content_frame_registrysettings, text="Registry Settings")
        self.notebook.add(self.content_frame_network, text="Network")
        self.notebook.add(self.content_frame_telemetry, text="Telemetry")
        self.notebook.add(self.content_frame_autostart, text="Autostart")
        
        # Create footer
        self.create_footer()
        
        # Initialize tweak UI map and groups
        self.tweak_ui_map = {}
        self.tweak_groups = {}
        
        # Populate tabs
        self.create_core_services_tab()
        self.create_update_clients_tab()
        self.create_scheduled_tasks_tab()
        self.create_registry_settings_tab()
        self.create_network_tab()
        self.create_telemetry_tab()
        self.create_autostart_tab()
        
        # Check for updates
        self.check_for_updates()
        
        # Check for admin rights
        self.check_admin_rights()
        
        # Process command line arguments
        self.process_command_line_args()
        
        # Refresh all tweak statuses
        self.refresh_all_tweak_statuses()

    def setup_styles(self):
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("Main.TFrame", background="#f0f0f0")
        style.configure("Content.TFrame", background="#f0f0f0")
        style.configure("Header.TLabel", font=("Arial", 12, "bold"), background="#f0f0f0")
        style.configure("Footer.TFrame", background="#e0e0e0")
        style.configure("TButton", font=("Arial", 10))
        style.configure("Status.TLabel", font=("Arial", 10, "bold"))
        style.configure("Description.TLabel", font=("Arial", 9), background="#f0f0f0")
        style.configure("AdminWarning.TLabel", foreground="red", font=("Arial", 10, "bold"), background="#f0f0f0")
        style.configure("UpdateAvailable.TLabel", foreground="blue", font=("Arial", 10, "bold"), background="#f0f0f0")
        style.configure("Tweak.TFrame", background="#f8f8f8", relief="groove", borderwidth=1)
        style.configure("TwheakHeader.TLabel", font=("Arial", 10, "bold"), background="#f8f8f8")

    def create_header(self):
        header_frame = ttk.Frame(self.main_frame, style="Main.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        ttk.Label(header_frame, text="Windows Update Tweaker", style="Header.TLabel").pack(side=tk.LEFT, padx=5)
        
        # Admin status
        self.admin_label = ttk.Label(header_frame, text="", style="AdminWarning.TLabel")
        self.admin_label.pack(side=tk.RIGHT, padx=5)
        
        # Update available
        self.update_label = ttk.Label(header_frame, text="", style="UpdateAvailable.TLabel")
        self.update_label.pack(side=tk.RIGHT, padx=5)
        
        # Active tweaks counter
        self.active_tweaks_label = ttk.Label(header_frame, text="Active Tweaks: 0/0", style="Status.TLabel")
        self.active_tweaks_label.pack(side=tk.RIGHT, padx=5)
        
        # Separator
        ttk.Separator(self.main_frame, orient="horizontal").pack(fill=tk.X, padx=10, pady=5)

    def create_footer(self):
        footer_frame = ttk.Frame(self.main_frame, style="Footer.TFrame")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        
        # Status bar
        self.status_bar = ttk.Label(footer_frame, text="Ready", anchor=tk.W)
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Buttons
        ttk.Button(footer_frame, text="Apply All", command=self.apply_all_recommended_tweaks).pack(side=tk.RIGHT, padx=2)
        ttk.Button(footer_frame, text="Undo All", command=self.undo_all_recommended_tweaks).pack(side=tk.RIGHT, padx=2)
        ttk.Button(footer_frame, text="Refresh", command=self.refresh_all_tweak_statuses).pack(side=tk.RIGHT, padx=2)
        ttk.Button(footer_frame, text="About", command=self.show_about).pack(side=tk.RIGHT, padx=2)
        ttk.Button(footer_frame, text="Exit", command=self.master.destroy).pack(side=tk.RIGHT, padx=2)

    def create_tweak_frame(self, parent, name, description, apply_func, undo_func, status_func, is_task=False, group_key=None):
        frame = ttk.Frame(parent, style="Tweak.TFrame")
        frame.pack(fill=tk.X, padx=10, pady=5, anchor="n")
        
        # Store in tweak UI map
        self.tweak_ui_map[name] = (None, status_func, apply_func, undo_func, is_task)
        
        # Add to group if specified
        if group_key:
            if group_key not in self.tweak_groups:
                self.tweak_groups[group_key] = []
            self.tweak_groups[group_key].append(name)
        
        # Top row: Name and status
        top_frame = ttk.Frame(frame, style="Content.TFrame")
        top_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(top_frame, text=name, style="TwheakHeader.TLabel").pack(side=tk.LEFT, padx=5)
        
        status_label = ttk.Label(top_frame, text="Checking...", style="Status.TLabel")
        status_label.pack(side=tk.RIGHT, padx=5)
        
        # Update tweak UI map with status label
        self.tweak_ui_map[name] = (status_label, status_func, apply_func, undo_func, is_task)
        
        # Middle row: Description
        if description:
            desc_frame = ttk.Frame(frame, style="Content.TFrame")
            desc_frame.pack(fill=tk.X, padx=5, pady=2)
            ttk.Label(desc_frame, text=description, style="Description.TLabel", wraplength=700).pack(side=tk.LEFT, padx=5)
        
        # Bottom row: Buttons
        button_frame = ttk.Frame(frame, style="Content.TFrame")
        button_frame.pack(fill=tk.X, padx=5, pady=2)
        
        apply_button = ttk.Button(button_frame, text="Apply", width=10, 
                                 command=lambda n=name: self.apply_tweak(n))
        apply_button.pack(side=tk.LEFT, padx=5)
        
        undo_button = ttk.Button(button_frame, text="Undo", width=10,
                                command=lambda n=name: self.undo_tweak(n))
        undo_button.pack(side=tk.LEFT, padx=5)
        
        return frame

    def apply_tweak(self, name):
        if name not in self.tweak_ui_map:
            log_message(f"Tweak {name} not found in UI map.")
            return
        
        status_label, status_func, apply_func, _, is_task = self.tweak_ui_map[name]
        
        # Check if this tweak is part of a group
        in_group = False
        group_key = None
        for key, names in self.tweak_groups.items():
            if name in names:
                in_group = True
                group_key = key
                break
        
        # Check if another tweak in the same group is active
        if in_group:
            for other_name in self.tweak_groups[group_key]:
                if other_name != name:
                    other_status_label, other_status_func, _, _, _ = self.tweak_ui_map[other_name]
                    other_status = other_status_func()
                    if is_tweak_active(other_status, other_name):
                        messagebox.showwarning("Tweak Conflict", 
                                              f"Cannot apply {name} because {other_name} is active. Please undo {other_name} first.",
                                              parent=self.master)
                        return
        
        # Apply the tweak
        action_description = "Applying" if not is_task else "Disabling"
        log_message(f"--- {action_description} tweak: {name} ---")
        
        self.status_bar.config(text=f"{action_description} {name}...")
        self.master.config(cursor="watch")
        self.master.update_idletasks()
        
        success = apply_func()
        
        self.master.config(cursor="")
        if success:
            self.status_bar.config(text=f"{name} applied successfully.")
            self.update_tweak_status(name)
            self.update_active_tweaks_count()
        else:
            self.status_bar.config(text=f"Failed to apply {name}.")
            messagebox.showerror("Apply Failed", f"Failed to apply {name}. Check the log for details.", parent=self.master)

    def undo_tweak(self, name):
        if name not in self.tweak_ui_map:
            log_message(f"Tweak {name} not found in UI map.")
            return
        
        status_label, status_func, _, undo_func, is_task = self.tweak_ui_map[name]
        
        # Undo the tweak
        action_description = "Undoing" if not is_task else "Enabling"
        log_message(f"--- {action_description} tweak: {name} ---")
        
        self.status_bar.config(text=f"{action_description} {name}...")
        self.master.config(cursor="watch")
        self.master.update_idletasks()
        
        success = undo_func()
        
        self.master.config(cursor="")
        if success:
            self.status_bar.config(text=f"{name} undone successfully.")
            self.update_tweak_status(name)
            self.update_active_tweaks_count()
        else:
            self.status_bar.config(text=f"Failed to undo {name}.")
            messagebox.showerror("Undo Failed", f"Failed to undo {name}. Check the log for details.", parent=self.master)

    def update_tweak_status(self, name):
        if name not in self.tweak_ui_map:
            log_message(f"Tweak {name} not found in UI map.")
            return
        
        status_label, status_func, _, _, _ = self.tweak_ui_map[name]
        status = status_func()
        
        status_text = get_status_display_text(status, name)
        status_color = get_status_color(status, name)
        
        status_label.config(text=status_text, foreground=status_color)

    def refresh_all_tweak_statuses(self):
        self.status_bar.config(text="Refreshing tweak statuses...")
        self.master.config(cursor="watch")
        self.master.update_idletasks()
        
        for name, (status_label, status_func, _, _, _) in self.tweak_ui_map.items():
            self.update_tweak_status(name)
        
        self.update_active_tweaks_count()
        
        self.master.config(cursor="")
        self.status_bar.config(text="Tweak statuses refreshed.")

    def update_active_tweaks_count(self):
        active_count = 0
        total_counted = 0
        counted_groups = set()
        
        # Iterate through all tweaks in the UI map
        for name, (status_label, status_func, _, _, _) in self.tweak_ui_map.items():
            status = status_func()
            # Exclude tweaks that are not found
            if status == "Not Found":
                continue
            # Determine if this tweak belongs to a group
            group_key = None
            for key, names in self.tweak_groups.items():
                if name in names:
                    group_key = key
                    break
            # Count unique groups or standalone tweaks
            if group_key:
                if group_key not in counted_groups:
                    counted_groups.add(group_key)
                    total_counted += 1
                    if is_tweak_active(status, name):
                        active_count += 1
            else:
                total_counted += 1
                if is_tweak_active(status, name):
                    active_count += 1
        
        # Update UI label
        if hasattr(self, "active_tweaks_label"):
            self.active_tweaks_label.config(text=f"Active Tweaks: {active_count}/{total_counted}")
            # Color based on percentage
            if total_counted > 0:
                percentage = active_count / total_counted
                if percentage > 0.7:
                    self.active_tweaks_label.config(foreground=COLOR_ACTIVE)
                elif percentage < 0.3:
                    self.active_tweaks_label.config(foreground=COLOR_INACTIVE)
                else:
                    self.active_tweaks_label.config(foreground=COLOR_NEUTRAL)
        
        log_message(f"Dashboard stats refreshed: Admin={is_admin_val}, ActiveTweaks={active_count}/{total_counted}")


    def apply_waaSMedic_tweak(self, silent=False):
        """
        Deaktiviert den Dienst WaaSMedicSvc und versucht nur dann, sedsvc.exe umzubenennen,
        wenn die Datei existiert.
        """
        # Dienst deaktivieren
        disable_service("WaaSMedicSvc", silent=silent)
        # Datei nur umbenennen, wenn sie existiert
        if os.path.exists(SEDSVC_PATH):
            apply_generic_file_rename(SEDSVC_PATH, SEDSVC_BAK_PATH, "sedsvc.exe", silent=silent)
        else:
            log_message("sedsvc.exe nicht gefunden; Umbenennung übersprungen.")
        return True

    def undo_waaSMedic_tweak(self, silent=False):
        """
        Reaktiviert den Dienst WaaSMedicSvc und stellt sedsvc.exe nur wieder her,
        wenn eine Backup-Datei vorhanden ist.
        """
        # Dienst aktivieren
        enable_service("WaaSMedicSvc", "manual", silent=silent)
        # Backup nur wiederherstellen, wenn sie existiert
        if os.path.exists(SEDSVC_BAK_PATH):
            undo_generic_file_rename(SEDSVC_PATH, SEDSVC_BAK_PATH, "sedsvc.exe", silent=silent)
        else:
            log_message("sedsvc.exe.bak nicht gefunden; Wiederherstellung übersprungen.")
        return True


    def _prepare_recommended_tweaks_actions(self):
        self.recommended_tweaks_actions = []
        self.recommended_tweaks_actions.extend([
            ("Windows Update Service (wuauserv)",
             lambda s=False: disable_service("wuauserv", silent=s),
             lambda s=False: enable_service("wuauserv", "manual", silent=s),
             lambda: get_service_status("wuauserv"),
             False),
            ("Update Orchestrator Service (UsoSvc)",
             lambda s=False: disable_service("UsoSvc", silent=s),
             lambda s=False: enable_service("UsoSvc", "auto", silent=s),
             lambda: get_service_status("UsoSvc"),
             False),
            ("Background Intelligent Transfer Service (BITS)",
             lambda s=False: disable_service("BITS", silent=s),
             lambda s=False: enable_service("BITS", "manual", silent=s),
             lambda: get_service_status("BITS"),
             False),
            ("Delivery Optimization (DoSvc)",
             lambda s=False: disable_service("DoSvc", silent=s),
             lambda s=False: enable_service("DoSvc", "auto", silent=s),
             lambda: get_service_status("DoSvc"),
             False),
            ("Rename wuauclt.exe",
             lambda s=False: apply_generic_file_rename(WUAUCLT_PATH, WUAUCLT_BAK_PATH, "wuauclt.exe", silent=s),
             lambda s=False: undo_generic_file_rename(WUAUCLT_PATH, WUAUCLT_BAK_PATH, "wuauclt.exe", silent=s),
             lambda: get_generic_file_status(WUAUCLT_PATH, WUAUCLT_BAK_PATH, "wuauclt.exe"),
             False),
            ("Rename UsoClient.exe",
             lambda s=False: apply_generic_file_rename(USOCLIENT_PATH, USOCLIENT_BAK_PATH, "UsoClient.exe", silent=s),
             lambda s=False: undo_generic_file_rename(USOCLIENT_PATH, USOCLIENT_BAK_PATH, "UsoClient.exe", silent=s),
             lambda: get_generic_file_status(USOCLIENT_PATH, USOCLIENT_BAK_PATH, "UsoClient.exe"),
             False),
            ("Disable Automatic Updates (NoAutoUpdate=1)",
             lambda s=False: apply_no_auto_update(silent=s),
             lambda s=False: undo_no_auto_update(silent=s),
             get_no_auto_update_status,
             False),
            ("Set Update Notifications Only (AUOptions=1)",
             lambda s=False: apply_auoptions_notify(silent=s),
             lambda s=False: undo_auoptions_notify(silent=s),
             get_auoptions_status,
             False),
            ("Do Not Use Internal WSUS (UseWUServer=0)",
             lambda s=False: apply_usewuserver_disable(silent=s),
             lambda s=False: undo_usewuserver_disable(silent=s),
             get_usewuserver_status,
             False),
            ("Disable Consumer Features (CloudContent)",
             lambda s=False: apply_disable_consumer_features(silent=s),
             lambda s=False: undo_disable_consumer_features(silent=s),
             get_disable_consumer_features_status,
             False),
            ("Block Domains (Hosts File)",
             lambda s=False: apply_hosts_block(silent=s),
             lambda s=False: undo_hosts_block(silent=s),
             get_hosts_status,
             False),
            ("Block IPs (Firewall Rule)",
             lambda s=False: apply_fw_block(silent=s),
             lambda s=False: undo_fw_block(silent=s),
             get_fw_status,
             False),
            ("Connected User Experiences and Telemetry (DiagTrack)",
             lambda s=False: disable_service("DiagTrack", silent=s),
             lambda s=False: enable_service("DiagTrack", "auto", silent=s),
             lambda: get_service_status("DiagTrack"),
             False),

            # Core Services
            ("Windows Update Medic Service (WaaSMedicSvc)",
             self.apply_waaSMedic_tweak,
             self.undo_waaSMedic_tweak,
             lambda: get_service_status("WaaSMedicSvc"),
             False),
            ("Windows Modules Installer (TrustedInstaller)",
             lambda s=False: disable_service("TrustedInstaller", silent=s),
             lambda s=False: enable_service("TrustedInstaller", "manual", silent=s),
             lambda: get_service_status("TrustedInstaller"),
             False),

            # Telemetry Extras
            ("Diagnostics Tracking Service (dmwappushservice)",
             lambda s=False: disable_service("dmwappushservice", silent=s),
             lambda s=False: enable_service("dmwappushservice", "auto", silent=s),
             lambda: get_service_status("dmwappushservice"),
             False),
            ("Windows Error Reporting Service (WerSvc)",
             lambda s=False: disable_service("WerSvc", silent=s),
             lambda s=False: enable_service("WerSvc", "manual", silent=s),
             lambda: get_service_status("WerSvc"),
             False),
            (OPTIONAL_TELEMETRY_SERVICES["WpnUserService"][0],
             lambda s=False, n=find_wpnuserservice_name(): disable_service(n, silent=s),
             lambda s=False, n=find_wpnuserservice_name(): enable_service(n, "auto", silent=s),
             lambda n=find_wpnuserservice_name(): get_service_status(n),
             False),
            ("Microsoft Compatibility Appraiser (Mcx2Svc)",
             lambda s=False: disable_service("Mcx2Svc", silent=s),
             lambda s=False: enable_service("Mcx2Svc", "manual", silent=s),
             lambda: get_service_status("Mcx2Svc"),
             False),

            # **Neu: Autostart-Task**
            ("Create Autostart Task",
             lambda s=False: create_startup_task(s),
             lambda s=False: delete_startup_task(s),
             lambda: get_startup_task_status(),
             False),
        ])

        for task_path in SCHEDULED_TASKS_TO_MANAGE:
            task_display_name = task_path.split("\\")[-1]
            self.recommended_tweaks_actions.append((
                f"Disable Task: {task_display_name}",
                lambda s=False, tp=task_path: disable_scheduled_task(tp, silent=s),
                lambda s=False, tp=task_path: enable_scheduled_task(tp, silent=s),
                lambda tp=task_path: get_scheduled_task_status(tp),
                True
            ))


    def _execute_all_actions(self, action_type="apply", silent=False):
        if not hasattr(self, "recommended_tweaks_actions") or not self.recommended_tweaks_actions:
            self._prepare_recommended_tweaks_actions()
        
        action_word = "Applying" if action_type == "apply" else "Undoing"
        confirm_message = f"This will attempt to {action_type.lower()} {len(self.recommended_tweaks_actions)} recommended tweaks. Continue?"
        
        log_message(f"_execute_all_actions called with action_type={action_type}, silent={silent}")
        
        # Führe Aktionen nur aus, wenn silent=True oder der Benutzer im Dialog "Ja" klickt
        proceed = silent
        if not silent:
            log_message("Showing confirmation dialog")
            proceed = messagebox.askyesno(f"Confirm {action_word} All", confirm_message, parent=self.master)
        else:
            log_message("Skipping confirmation dialog due to silent mode")
        
        if proceed:
            log_message(f"Proceeding with {action_word} tweaks")
            def _process_all_task():
                if not silent:
                    self.master.config(cursor="watch")
                    self.status_bar.config(text=f"{action_word} all recommended tweaks...")
                log_message(f"--- {action_word} all recommended tweaks started ---")
                
                processed_count = 0
                for name, apply_func, undo_func, status_func, is_task_action in self.recommended_tweaks_actions:
                    action_to_take = apply_func if action_type == "apply" else undo_func
                    if not silent:
                        self.status_bar.config(text=f"{action_word} ({processed_count+1}/{len(self.recommended_tweaks_actions)}): {name}")
                    try:
                        action_to_take(True)  # Execute silently
                    except Exception as e:
                        log_message(f"Error during {action_word} {name}: {e}")
                    processed_count += 1
                    time.sleep(0.05)  # Small delay to allow processing

                if not silent:
                    self.master.after(0, self.refresh_all_tweak_statuses)
                    self.master.after(0, lambda: self.master.config(cursor=""))
                    self.master.after(0, lambda: self.status_bar.config(text=f"All recommended tweaks {action_type} process completed. Check logs for details."))
                log_message(f"--- {action_word} all recommended tweaks finished ---")
            
            log_message("Starting tweak application thread")
            threading.Thread(target=_process_all_task, daemon=True).start()
        else:
            log_message(f"{action_word} tweaks cancelled")
        
    def apply_all_recommended_tweaks(self):
        self._execute_all_actions(action_type="apply")

    def undo_all_recommended_tweaks(self):
        self._execute_all_actions(action_type="undo")

    def create_core_services_tab(self):
        parent = self.content_frame_coreservices
        ttk.Label(parent, text="Manage Core Update and Related Services", style="Header.TLabel").pack(pady=10, anchor="w")

        tweaks = [
            (
                "Windows Update Service (wuauserv)",
                "Stops & disables the main Windows Update service.",
                lambda silent=False: disable_service("wuauserv", silent=silent),
                lambda silent=False: enable_service("wuauserv", "manual", silent=silent),
                lambda: get_service_status("wuauserv")
            ),
            (
                "Update Orchestrator Service (UsoSvc)",
                "Stops & disables the Update Orchestrator Service.",
                lambda silent=False: disable_service("UsoSvc", silent=silent),
                lambda silent=False: enable_service("UsoSvc", "auto", silent=silent),
                lambda: get_service_status("UsoSvc")
            ),
            (
                "Windows Update Medic Service (WaaSMedicSvc)",
                "Stops & disables WaaSMedicSvc and renames sedsvc.exe, wenn vorhanden.",
                self.apply_waaSMedic_tweak,
                self.undo_waaSMedic_tweak,
                lambda: get_service_status("WaaSMedicSvc")
            ),
            (
                "Background Intelligent Transfer Service (BITS)",
                "Stops & disables BITS.",
                lambda silent=False: disable_service("BITS", silent=silent),
                lambda silent=False: enable_service("BITS", "manual", silent=silent),
                lambda: get_service_status("BITS")
            ),
            (
                "Delivery Optimization (DoSvc)",
                "Stops & disables Delivery Optimization service.",
                lambda silent=False: disable_service("DoSvc", silent=silent),
                lambda silent=False: enable_service("DoSvc", "auto", silent=silent),
                lambda: get_service_status("DoSvc")
            ),
            (
                "Windows Modules Installer (TrustedInstaller)",
                "Stops & disables TrustedInstaller. CRITICAL: May break system updates/repairs if disabled long-term.",
                lambda silent=False: disable_service("TrustedInstaller", silent=silent),
                lambda silent=False: enable_service("TrustedInstaller", "manual", silent=silent),
                lambda: get_service_status("TrustedInstaller")
            ),
        ]

        for name, desc, apply_f, undo_f, status_f in tweaks:
            self.create_tweak_frame(
                parent,
                name,
                desc,
                apply_f,
                undo_f,
                status_f
            )


    def create_update_clients_tab(self): 
        parent = self.content_frame_updateclients; ttk.Label(parent, text="Manage Update Client Executables", style="Header.TLabel").pack(pady=10, anchor="w")
        file_tweaks = [
            ("wuauclt.exe", WUAUCLT_PATH, WUAUCLT_BAK_PATH),
            ("UsoClient.exe", USOCLIENT_PATH, USOCLIENT_BAK_PATH),
        ]
        for ft_name, ft_path, ft_bak_path in file_tweaks:
            group_key = f"file_{ft_name}"
            self.create_tweak_frame(parent, f"Lock {ft_name}", f"Deny Everyone Write to {ft_name} (ACLs).", 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: apply_generic_file_lock(p,b,n), 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: undo_generic_file_lock(p,b,n), 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: get_generic_file_status(p,b,n),
                                    group_key=group_key)
            self.create_tweak_frame(parent, f"Rename {ft_name}", f"Rename {ft_name} to {os.path.basename(ft_bak_path)}.", 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: apply_generic_file_rename(p,b,n), 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: undo_generic_file_rename(p,b,n), 
                                    lambda p=ft_path,b=ft_bak_path,n=ft_name: get_generic_file_status(p,b,n),
                                    group_key=group_key)

    def create_scheduled_tasks_tab(self):
        parent = self.content_frame_scheduledtasks
        ttk.Label(parent, text="Manage Update-Related Scheduled Tasks", style="Header.TLabel").pack(pady=10, anchor="w", padx=10)
        ttk.Label(parent, text="Disable these tasks to further prevent unexpected update activities.", wraplength=700).pack(pady=(0,10), anchor="w", padx=10)
        
        # Canvas and Scrollbar for tasks
        canvas = tk.Canvas(parent, borderwidth=0, background="#f0f0f0")
        task_list_frame = ttk.Frame(canvas, style="Content.TFrame")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas_frame_id = canvas.create_window((0,0), window=task_list_frame, anchor="nw")

        def _on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        task_list_frame.bind("<Configure>", _on_frame_configure)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel) # Bind to all for wider scroll capture

        for task_name in SCHEDULED_TASKS_TO_MANAGE:
            display_name = task_name.split("\\")[-1]
            info = f"Manages the scheduled task: {task_name}"
            self.create_tweak_frame(task_list_frame, f"Task: {display_name}", info, 
                                      lambda tn=task_name: disable_scheduled_task(tn), 
                                      lambda tn=task_name: enable_scheduled_task(tn), 
                                      lambda tn=task_name: get_scheduled_task_status(tn),
                                      is_task=True)
        task_list_frame.update_idletasks() # Ensure frame size is calculated for scrollregion
        canvas.config(scrollregion=canvas.bbox("all"))

    def create_registry_settings_tab(self):
        parent = self.content_frame_registrysettings; ttk.Label(parent, text="Configure Windows Update & Cloud Content via Registry", style="Header.TLabel").pack(pady=10, anchor="w")
        reg_tweaks = [
            ("Disable Automatic Updates (NoAutoUpdate=1)", "Sets NoAutoUpdate=1. Disables auto-downloads/installs.", apply_no_auto_update, undo_no_auto_update, get_no_auto_update_status),
            ("Set Update Notifications Only (AUOptions=1)", "Sets AUOptions=1 (Notify before download/install).", apply_auoptions_notify, undo_auoptions_notify, get_auoptions_status),
            ("Do Not Use Internal WSUS (UseWUServer=0)", "Sets UseWUServer=0. Prevents use of internal WSUS server.", apply_usewuserver_disable, undo_usewuserver_disable, get_usewuserver_status),
            ("Disable Consumer Features (CloudContent)", "Disables Windows consumer features and suggestions.", apply_disable_consumer_features, undo_disable_consumer_features, get_disable_consumer_features_status),
        ]
        for name, desc, apply_f, undo_f, status_f in reg_tweaks:
            self.create_tweak_frame(parent, name, desc, apply_f, undo_f, status_f)

    def create_network_tab(self):
        parent = self.content_frame_network; ttk.Label(parent, text="Block Windows Update & Telemetry Network Traffic", style="Header.TLabel").pack(pady=10, anchor="w")
        network_tweaks = [
            ("Block Domains (Hosts File)", "Adds Windows Update & telemetry domains to hosts file with 127.0.0.1 entries.", apply_hosts_block, undo_hosts_block, get_hosts_status),
            ("Block IPs (Firewall Rule)", "Creates outbound firewall rule to block Windows Update & telemetry servers.", apply_fw_block, undo_fw_block, get_fw_status),
        ]
        for name, desc, apply_f, undo_f, status_f in network_tweaks:
            self.create_tweak_frame(parent, name, desc, apply_f, undo_f, status_f)

    def create_telemetry_tab(self):
        parent = self.content_frame_telemetry; ttk.Label(parent, text="Disable Windows Telemetry & Diagnostic Services", style="Header.TLabel").pack(pady=10, anchor="w")
        telemetry_tweaks = [
            ("Connected User Experiences and Telemetry (DiagTrack)", "Stops & disables the main Windows telemetry service.", 
             lambda silent=False: disable_service("DiagTrack", silent=silent), 
             lambda silent=False: enable_service("DiagTrack", "auto", silent=silent), 
             lambda: get_service_status("DiagTrack")),
            ("Diagnostics Tracking Service (dmwappushservice)", "Stops & disables the diagnostics tracking service.", 
             lambda silent=False: disable_service("dmwappushservice", silent=silent), 
             lambda silent=False: enable_service("dmwappushservice", "auto", silent=silent), 
             lambda: get_service_status("dmwappushservice")),
            ("Windows Error Reporting Service (WerSvc)", "Stops & disables the error reporting service.", 
             lambda silent=False: disable_service("WerSvc", silent=silent), 
             lambda silent=False: enable_service("WerSvc", "manual", silent=silent), 
             lambda: get_service_status("WerSvc")),
        ]
        for name, desc, apply_f, undo_f, status_f in telemetry_tweaks:
            self.create_tweak_frame(parent, name, desc, apply_f, undo_f, status_f)
        
        # Add dynamic WpnUserService
        wpn_name = find_wpnuserservice_name()
        if wpn_name:
            display_name, desc = OPTIONAL_TELEMETRY_SERVICES["WpnUserService"]
            self.create_tweak_frame(parent, display_name, desc, 
                                   lambda silent=False, n=wpn_name: disable_service(n, silent=silent), 
                                   lambda silent=False, n=wpn_name: enable_service(n, "auto", silent=silent), 
                                   lambda n=wpn_name: get_service_status(n))
        
        # Add Mcx2Svc
        display_name, desc = OPTIONAL_TELEMETRY_SERVICES["Mcx2Svc"]
        self.create_tweak_frame(parent, display_name, desc, 
                               lambda silent=False: disable_service("Mcx2Svc", silent=silent), 
                               lambda silent=False: enable_service("Mcx2Svc", "manual", silent=silent), 
                               lambda: get_service_status("Mcx2Svc"))

    def create_autostart_tab(self):
        parent = self.content_frame_autostart; ttk.Label(parent, text="Configure Autostart Options", style="Header.TLabel").pack(pady=10, anchor="w")
        ttk.Label(parent, text="Set up Windows Update Tweaker to run automatically at system startup.", wraplength=700).pack(pady=(0,10), anchor="w", padx=10)
        
        self.create_tweak_frame(parent, "Create Autostart Task", 
                               "Creates a scheduled task to run Windows Update Tweaker at logon with highest privileges.", 
                               create_startup_task, 
                               delete_startup_task, 
                               get_startup_task_status)
        
        # Add silent autorun info
        info_frame = ttk.Frame(parent, style="Content.TFrame")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(info_frame, text="Note: When run at startup, the program will automatically apply all recommended tweaks without showing the GUI. To disable this behavior, remove the autostart task.", 
                 wraplength=700, style="Description.TLabel").pack(pady=10, padx=10, anchor="w")
        
        # Add command line arguments info
        cmd_frame = ttk.Frame(parent, style="Content.TFrame")
        cmd_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(cmd_frame, text="Command Line Arguments:", style="TwheakHeader.TLabel").pack(pady=(10,5), padx=10, anchor="w")
        ttk.Label(cmd_frame, text="--autorun-silent: Apply all recommended tweaks silently and exit\n--check-only: Check tweak status and exit without applying anything", 
                 wraplength=700, style="Description.TLabel").pack(pady=5, padx=10, anchor="w")

    def check_for_updates(self):
        def _check_update_thread():
            try:
                with url_request.urlopen(GITHUB_REPO_URL, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    latest_version = data.get("tag_name", "").strip("v")
                    if latest_version and latest_version != APP_VERSION:
                        self.master.after(0, lambda: self.update_label.config(
                            text=f"Update Available: v{latest_version}",
                            cursor="hand2"
                        ))
                        self.update_label.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_RELEASES_PAGE_URL))
            except Exception as e:
                log_message(f"Failed to check for updates: {e}")
        
        threading.Thread(target=_check_update_thread, daemon=True).start()

    def check_admin_rights(self):
        global is_admin_val
        import ctypes
        try:
            is_admin_val = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin_val:
                self.admin_label.config(text="Not Running as Admin!")
                messagebox.showwarning("Admin Rights Required", 
                                      "This program is not running with administrator privileges. Some functions may not work correctly.", 
                                      parent=self.master)
            else:
                self.admin_label.config(text="Admin: Yes")
        except Exception as e:
            log_message(f"Admin check failed: {e}")
            self.admin_label.config(text="Admin Check Failed")

    def process_command_line_args(self):
        if len(sys.argv) > 1:
            if "--autorun-silent" in sys.argv:
                log_message("Autorun silent mode detected. Applying all recommended tweaks...")
                self._execute_all_actions(action_type="apply", silent=True)
                log_message("Silent mode tweaks applied. Exiting...")
                self.master.after(1000, self.master.destroy)
            elif "--check-only" in sys.argv:
                log_message("Check-only mode detected. Checking tweak status...")
                self.refresh_all_tweak_statuses()
                log_message("Check-only mode completed. Exiting...")
                self.master.after(1000, self.master.destroy)

    def show_about(self):
        about_text = f"""Windows Update Tweaker v{APP_VERSION}

A tool to manage Windows Update and related services.

Features:
- Disable Windows Update services
- Block Windows Update network traffic
- Disable telemetry and diagnostic services
- Manage scheduled tasks
- Configure registry settings

This program is free software under the MIT License.

Check for updates: {GITHUB_RELEASES_PAGE_URL}
"""
        about_dialog = tk.Toplevel(self.master)
        about_dialog.title("About Windows Update Tweaker")
        about_dialog.geometry("400x320")
        about_dialog.resizable(False, False)
        about_dialog.transient(self.master)
        about_dialog.grab_set()
        
        # Center the dialog on the main window
        about_dialog.geometry("+%d+%d" % (
            self.master.winfo_rootx() + self.master.winfo_width() // 2 - 200,
            self.master.winfo_rooty() + self.master.winfo_height() // 2 - 150
        ))
        
        # Add content
        frame = ttk.Frame(about_dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(frame, text=f"Windows Update Tweaker v{APP_VERSION}", font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Description
        desc_text = tk.Text(frame, wrap=tk.WORD, height=10, width=40)
        desc_text.insert(tk.END, about_text)
        desc_text.config(state=tk.DISABLED)
        desc_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Check for updates button
        update_frame = ttk.Frame(frame)
        update_frame.pack(fill=tk.X, pady=10)
        
        update_button = ttk.Button(update_frame, text="Check for Updates", 
                                  command=lambda: self.check_for_updates_from_about(update_status_label))
        update_button.pack(side=tk.LEFT, padx=5)
        
        update_status_label = ttk.Label(update_frame, text="")
        update_status_label.pack(side=tk.LEFT, padx=5)
        
        # Close button
        close_button = ttk.Button(frame, text="Close", command=about_dialog.destroy)
        close_button.pack(pady=10)

    def check_for_updates_from_about(self, status_label):
        """Check for updates from the About dialog and update the status label."""
        status_label.config(text="Checking for updates...")
        
        def _check_update_thread():
            try:
                with url_request.urlopen(GITHUB_REPO_URL, timeout=5) as response:
                    data = json.loads(response.read().decode())
                    latest_version = data.get("tag_name", "").strip("v")
                    if latest_version and latest_version != APP_VERSION:
                        self.master.after(0, lambda: status_label.config(
                            text=f"Update available: v{latest_version}",
                            foreground="blue",
                            cursor="hand2"
                        ))
                        status_label.bind("<Button-1>", lambda e: webbrowser.open(GITHUB_RELEASES_PAGE_URL))
                    else:
                        self.master.after(0, lambda: status_label.config(
                            text="You have the latest version.",
                            foreground="green"
                        ))
            except Exception as e:
                log_message(f"Failed to check for updates: {e}")
                self.master.after(0, lambda: status_label.config(
                    text="Failed to check for updates.",
                    foreground="red"
                ))
        
        threading.Thread(target=_check_update_thread, daemon=True).start()

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    is_admin_val = False
    log_message(f"Command line arguments: {sys.argv}")

    if "--autorun-silent" in sys.argv:
        log_message("Autorun silent mode detected. Applying all recommended tweaks...")
        root = tk.Tk()
        root.withdraw()
        app = WindowsUpdateTweakerGUI(root)
        log_message("Calling _execute_all_actions with silent=True")
        app._execute_all_actions(action_type="apply", silent=True)
        log_message("Silent mode tweaks applied. Exiting...")
        root.destroy()
        sys.exit(0)
    elif "--check-only" in sys.argv:
        log_message("Check-only mode detected. Checking tweak status...")
        root = tk.Tk()
        root.withdraw()
        app = WindowsUpdateTweakerGUI(root)
        app.refresh_all_tweak_statuses()
        log_message("Check-only mode completed. Exiting...")
        root.destroy()
        sys.exit(0)

    log_message("Starting GUI mode")
    root = tk.Tk()
    app = WindowsUpdateTweakerGUI(root)
    root.mainloop()
