import os
import sys
import subprocess
import winreg
import shutil
import tkinter as tk
from tkinter import messagebox, font
import datetime
import socket # Added for DNS lookup

# --- Logging Setup ---
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "tweak_log.txt")

def log_message(message):
    """Appends a message to the log file with a timestamp."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception as e:
        print(f"Logging failed: {e}", file=sys.stderr)

log_message("--- Script started ---")

if os.name != 'nt':
    log_message("Error: This script only runs on Windows.")
    messagebox.showerror("Error", "This script only runs on Windows.")
    sys.exit(1)

ADMINISTRATORS_SID = "*S-1-5-32-544"
EVERYONE_SID       = "*S-1-1-0"

# ---------------------------
# Helper: run shell commands
# ---------------------------
def run_cmd(cmd):
    log_message(f"Executing: {cmd}")
    result = {'success': False, 'stdout': '', 'stderr': '', 'returncode': -1}
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        proc = subprocess.run(
            cmd, shell=True, 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, startupinfo=si,
            encoding="utf-8", errors="ignore"
        )
        result['stdout'] = proc.stdout.strip()
        result['stderr'] = proc.stderr.strip()
        result['returncode'] = proc.returncode
        if proc.returncode == 0:
            result['success'] = True
            log_message(f"Success: {cmd}\nStdout: {result['stdout']}\nStderr: {result['stderr']}")
        else:
            log_message(f"Command non-zero exit: {cmd}\nReturn Code: {proc.returncode}\nStdout: {result['stdout']}\nStderr: {result['stderr']}")
    except subprocess.CalledProcessError as e: 
        result['stderr'] = str(e)
        result['returncode'] = e.returncode if hasattr(e, 'returncode') else -1
        log_message(f"Failed (CalledProcessError): {cmd}\nError: {e}\nStdout: {e.stdout if hasattr(e, 'stdout') else ''}\nStderr: {e.stderr if hasattr(e, 'stderr') else ''}")
    except Exception as ex:
        result['stderr'] = str(ex)
        log_message(f"Exception in run_cmd('{cmd}'): {ex}")
    return result

# ---------------------------
# Paths & constants
# ---------------------------
HOSTS_PATH       = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_ENTRIES    = [
    "127.0.0.1 windowsupdate.microsoft.com",
    "127.0.0.1 *.windowsupdate.microsoft.com"
]
WUAUCLT_PATH     = r"C:\Windows\System32\wuauclt.exe"
WUAUCLT_BAK_PATH = WUAUCLT_PATH + ".bak"

UPDATE_TASKS = [
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work",
    r"\Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work",
    r"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker",
    r"\Microsoft\Windows\WindowsUpdate\Automatic App Update",
    r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
    r"\Microsoft\Windows\WindowsUpdate\sih",
    r"\Microsoft\Windows\WindowsUpdate\sihboot"
]

FW_RULE_NAME = "Block Windows Update Domains (DNS Resolved)"
FW_HOSTNAMES_TO_BLOCK = [
    "windowsupdate.microsoft.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "delivery.mp.microsoft.com",
    "sls.update.microsoft.com",
    "fe2.update.microsoft.com",
    "displaycatalog.mp.microsoft.com",
    "tsfe.trafficshaping.dsp.mp.microsoft.com", 
    "v10.events.data.microsoft.com"
]

# ---------------------------
# DNS Lookup for Firewall
# ---------------------------
def resolve_hostnames_to_ips(hostnames):
    log_message(f"Attempting to resolve hostnames: {hostnames}")
    resolved_ips = set()
    for hostname in hostnames:
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for info in addr_info:
                ip_address = info[4][0]
                if ':' not in ip_address: 
                    resolved_ips.add(ip_address)
                    log_message(f"Resolved {hostname} to IPv4: {ip_address}")
                    break 
            else: 
                if addr_info:
                    ip_address = addr_info[0][4][0]
                    resolved_ips.add(ip_address)
                    log_message(f"Resolved {hostname} to (possibly IPv6): {ip_address}")
        except socket.gaierror as e:
            log_message(f"DNS resolution failed for {hostname}: {e}")
        except Exception as e:
            log_message(f"Unexpected error resolving {hostname}: {e}")
    
    if not resolved_ips:
        log_message("No IPs were resolved from the given hostnames.")
        return ""
    return ",".join(list(resolved_ips))

# ---------------------------
# Status Utility
# ---------------------------
def get_file_status():
    log_message(f"Checking file status for {WUAUCLT_PATH}")
    if os.path.exists(WUAUCLT_BAK_PATH) and not os.path.exists(WUAUCLT_PATH):
        log_message(f"Status: Renamed ({WUAUCLT_BAK_PATH} exists, {WUAUCLT_PATH} does not)")
        return "Renamed"
    if os.path.exists(WUAUCLT_PATH):
        try:
            cmd_result = run_cmd(f'icacls "{WUAUCLT_PATH}"')
            if cmd_result['success']:
                out = cmd_result['stdout']
                log_message(f"icacls output for {WUAUCLT_PATH}:\n{out}")
                if "Jeder:(DENY)(W)" in out or "Everyone:(DENY)(W)" in out:
                    log_message(f"Status: Locked (DENY Everyone/Jeder Write rule found)")
                    return "Locked"
            else:
                log_message(f"icacls command failed for {WUAUCLT_PATH} while checking status: {cmd_result['stderr']}")
        except Exception as e:
            log_message(f"Error checking file ACLs for {WUAUCLT_PATH}: {e}")
    log_message(f"Status: Writable (or state undetermined if not Renamed/Locked)")
    return "Writable"

def get_tasks_status():
    log_message("Checking summary status of scheduled tasks...") # Clarified log message
    disabled_count = 0
    missing_count = 0
    enabled_count = 0 
    for task_path in UPDATE_TASKS:
        # Reduced logging for individual task queries unless an error occurs during query
        cmd_result = run_cmd(f'schtasks /Query /TN "{task_path}" /FO CSV /NH')
        if cmd_result['success'] and cmd_result['stdout']:
            try:
                status_line = cmd_result['stdout'].splitlines()[0]
                task_status = status_line.split(',')[-1].strip().replace('"', '').lower()
                if task_status == "disabled" or task_status == "deaktiviert":
                    disabled_count += 1
                else:
                    enabled_count +=1
            except IndexError:
                log_message(f"Could not parse status for task '{task_path}'. Output: {cmd_result['stdout']}")
                enabled_count +=1 
        elif "nicht vorhanden" in cmd_result['stderr'].lower() or "does not exist" in cmd_result['stderr'].lower() or "cannot find the file specified" in cmd_result['stderr'].lower():
            missing_count += 1
        else:
            log_message(f"Failed to query task '{task_path}'. Error: {cmd_result['stderr']}")
            enabled_count +=1 

    if enabled_count > 0:
        log_message(f"Task status summary: Enabled: {enabled_count}, Disabled: {disabled_count}, Missing: {missing_count} -> Mixed")
        return "Mixed"
    if disabled_count > 0 and enabled_count == 0:
        log_message(f"Task status summary: Enabled: {enabled_count}, Disabled: {disabled_count}, Missing: {missing_count} -> Disabled")
        return "Disabled"
    if (disabled_count + missing_count) == len(UPDATE_TASKS) and enabled_count == 0:
        log_message(f"Task status summary: Enabled: {enabled_count}, Disabled: {disabled_count}, Missing: {missing_count} -> Disabled (all are disabled or missing)")
        return "Disabled"
    log_message(f"Task status summary: Enabled: {enabled_count}, Disabled: {disabled_count}, Missing: {missing_count} -> Unknown")
    return "Unknown"

def get_fw_status():
    log_message(f"Checking firewall rule status for '{FW_RULE_NAME}'...")
    # Using verbose for potentially more stable output, though not strictly necessary for 'Enabled' check.
    cmd_result = run_cmd(f'netsh advfirewall firewall show rule name="{FW_RULE_NAME}" verbose') 
    
    if not cmd_result['success']:
        if "No rules match the specified criteria" in cmd_result['stdout'] or \
           "No rules match the specified criteria" in cmd_result['stderr'] or \
           "Keine Regeln stimmen mit den angegebenen Kriterien überein" in cmd_result['stdout'] or \
           "Keine Regeln stimmen mit den angegebenen Kriterien überein" in cmd_result['stderr']:
            log_message(f"Firewall rule '{FW_RULE_NAME}' not found (command failed but indicated no rule). Status: Unblocked")
            return "Unblocked"
        log_message(f"Error checking firewall rule '{FW_RULE_NAME}': {cmd_result['stderr']} (stdout: {cmd_result['stdout']}). Status: Unknown")
        return "Unknown"

    if "No rules match the specified criteria" in cmd_result['stdout'] or \
       "Keine Regeln stimmen mit den angegebenen Kriterien überein" in cmd_result['stdout']:
        log_message(f"Firewall rule '{FW_RULE_NAME}' not found (command success but indicated no rule). Status: Unblocked")
        return "Unblocked"

    rule_enabled = False
    for line in cmd_result['stdout'].splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith("Enabled:") or stripped_line.startswith("Aktiviert:"):
            parts = stripped_line.split(':', 1)
            if len(parts) > 1:
                value_part = parts[1].strip().lower()
                if value_part == "yes" or value_part == "ja":
                    rule_enabled = True
                    break
    
    if rule_enabled:
         log_message(f"Firewall rule '{FW_RULE_NAME}' is Enabled. Status: Blocked")
         return "Blocked"
    else:
         log_message(f"Firewall rule '{FW_RULE_NAME}' is present but not detected as Enabled. Full output for check:\n{cmd_result['stdout']}. Status: Unblocked")
         return "Unblocked"

# ---------------------------
# Revised File Lock & Rename
# ---------------------------
def apply_file_lock_revised():
    log_message(f"Attempting to lock {WUAUCLT_PATH}...")
    if os.path.exists(WUAUCLT_BAK_PATH) and not os.path.exists(WUAUCLT_PATH):
        messagebox.showwarning("Lock Error", f"Cannot lock {os.path.basename(WUAUCLT_PATH)} because it is renamed. Please undo rename first.")
        return False
    if get_file_status() == "Locked":
        messagebox.showinfo("Already Locked", f"{os.path.basename(WUAUCLT_PATH)} is already locked.")
        return True
    if not run_cmd(f'takeown /f "{WUAUCLT_PATH}" /A')['success']: return False
    if not run_cmd(f'icacls "{WUAUCLT_PATH}" /grant {ADMINISTRATORS_SID}:F')['success']:
        run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')
        return False
    if not run_cmd(f'icacls "{WUAUCLT_PATH}" /deny {EVERYONE_SID}:(W)')['success']:
        run_cmd(f'icacls "{WUAUCLT_PATH}" /remove:d {EVERYONE_SID}')
        run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')
        return False
    return True

def undo_file_lock_revised():
    log_message(f"Attempting to unlock {WUAUCLT_PATH}...")
    if not os.path.exists(WUAUCLT_PATH):
        if os.path.exists(WUAUCLT_BAK_PATH):
             messagebox.showinfo("Unlock Info", f"{os.path.basename(WUAUCLT_PATH)} is renamed. Lock does not apply.")
             return True
        messagebox.showwarning("Unlock Error", f"{os.path.basename(WUAUCLT_PATH)} not found.")
        return False
    run_cmd(f'takeown /f "{WUAUCLT_PATH}" /A') 
    if not run_cmd(f'icacls "{WUAUCLT_PATH}" /grant {ADMINISTRATORS_SID}:F')['success']:
        run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')
        return False
    run_cmd(f'icacls "{WUAUCLT_PATH}" /remove:d {EVERYONE_SID}')
    return run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')['success']

def apply_file_rename_revised():
    log_message(f"Attempting to rename {WUAUCLT_PATH}...")
    if get_file_status() == "Locked":
        messagebox.showwarning("Rename Error", f"Cannot rename {os.path.basename(WUAUCLT_PATH)} as it is locked. Please unlock first.")
        return False
    if os.path.exists(WUAUCLT_BAK_PATH):
        messagebox.showinfo("Info", f"{os.path.basename(WUAUCLT_PATH)} is already renamed.")
        return True
    if not os.path.exists(WUAUCLT_PATH):
        messagebox.showwarning("Rename Error", f"{os.path.basename(WUAUCLT_PATH)} not found.")
        return False
    if not run_cmd(f'takeown /f "{WUAUCLT_PATH}" /A')['success']: return False
    if not run_cmd(f'icacls "{WUAUCLT_PATH}" /grant {ADMINISTRATORS_SID}:F')['success']:
        run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')
        return False
    try:
        os.rename(WUAUCLT_PATH, WUAUCLT_BAK_PATH)
        log_message(f"Successfully renamed {WUAUCLT_PATH} to {WUAUCLT_BAK_PATH}.")
        return True
    except OSError as e:
        log_message(f"Failed to rename {WUAUCLT_PATH} to {WUAUCLT_BAK_PATH}: {e}")
        run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')
        return False

def undo_file_rename_revised():
    log_message(f"Attempting to undo rename for {WUAUCLT_PATH}...")
    if not os.path.exists(WUAUCLT_BAK_PATH):
        if os.path.exists(WUAUCLT_PATH):
             messagebox.showinfo("Undo Rename", f"{os.path.basename(WUAUCLT_PATH)} not renamed or already restored.")
             return True
        messagebox.showwarning("Undo Rename Error", f"Backup file {os.path.basename(WUAUCLT_BAK_PATH)} not found.")
        return False
    if os.path.exists(WUAUCLT_PATH):
        messagebox.showerror("Undo Rename Error", f"{os.path.basename(WUAUCLT_PATH)} already exists. Cannot restore backup.")
        return False
    run_cmd(f'takeown /f "{WUAUCLT_BAK_PATH}" /A')
    if not run_cmd(f'icacls "{WUAUCLT_BAK_PATH}" /grant {ADMINISTRATORS_SID}:F')['success']: return False
    try:
        os.rename(WUAUCLT_BAK_PATH, WUAUCLT_PATH)
        log_message(f"Successfully renamed {WUAUCLT_BAK_PATH} back to {WUAUCLT_PATH}.")
    except OSError as e:
        log_message(f"Failed to rename {WUAUCLT_BAK_PATH} back to {WUAUCLT_PATH}: {e}")
        return False
    run_cmd(f'takeown /f "{WUAUCLT_PATH}" /A')
    run_cmd(f'icacls "{WUAUCLT_PATH}" /grant {ADMINISTRATORS_SID}:F')
    return run_cmd(f'icacls "{WUAUCLT_PATH}" /setowner "NT SERVICE\\TrustedInstaller" /T /C /L /Q')['success']

# ---------------------------
# Scheduled Tasks Tweak
# ---------------------------
def apply_tasks_disable():
    log_message("Attempting to disable scheduled tasks...")
    overall_success = True
    admin_warning_shown = False
    for task_path in UPDATE_TASKS:
        log_message(f"Processing task for disable: {task_path}")
        query_result = run_cmd(f'schtasks /Query /TN "{task_path}" /FO CSV /NH')
        if query_result['success'] and query_result['stdout']:
            try:
                status_line = query_result['stdout'].splitlines()[0]
                current_status = status_line.split(',')[-1].strip().replace('"', '').lower()
                if current_status == "disabled" or current_status == "deaktiviert":
                    log_message(f"Task '{task_path}' is already disabled. Skipping disable command.")
                    continue 
            except IndexError:
                log_message(f"Could not parse current status for task '{task_path}'. Proceeding with disable attempt.")
        elif "nicht vorhanden" in query_result['stderr'].lower() or "does not exist" in query_result['stderr'].lower() or "cannot find the file specified" in query_result['stderr'].lower():
            log_message(f"Task '{task_path}' does not exist. Skipping disable command.")
            continue 
        
        cmd_result = run_cmd(f'schtasks /Change /TN "{task_path}" /Disable')
        if not cmd_result['success']:
            log_message(f"Failed to disable task '{task_path}'. Error: {cmd_result['stderr']}")
            if ("Zugriff verweigert" in cmd_result['stderr'] or "Access is denied" in cmd_result['stderr'].lower()) and not admin_warning_shown:
                messagebox.showwarning("Task Error", f"Access denied for task: {task_path}.\nEnsure script is run as Administrator.\nSome tasks may require SYSTEM privileges.")
                admin_warning_shown = True
            overall_success = False
        else:
            log_message(f"Successfully disabled task '{task_path}'.")
    return overall_success

def undo_tasks_disable():
    log_message("Attempting to enable scheduled tasks...")
    overall_success = True
    admin_warning_shown = False
    for task_path in UPDATE_TASKS:
        log_message(f"Processing task for enable: {task_path}")
        query_result = run_cmd(f'schtasks /Query /TN "{task_path}" /FO CSV /NH')
        if query_result['success'] and query_result['stdout']:
            try:
                status_line = query_result['stdout'].splitlines()[0]
                current_status = status_line.split(',')[-1].strip().replace('"', '').lower()
                if current_status != "disabled" and current_status != "deaktiviert":
                    log_message(f"Task '{task_path}' is already enabled (status: {current_status}). Skipping enable command.")
                    continue
            except IndexError:
                log_message(f"Could not parse current status for task '{task_path}' for undo. Proceeding with enable attempt.")
        elif "nicht vorhanden" in query_result['stderr'].lower() or "does not exist" in query_result['stderr'].lower() or "cannot find the file specified" in query_result['stderr'].lower():
            log_message(f"Task '{task_path}' does not exist. Skipping enable command.")
            continue 
            
        cmd_result = run_cmd(f'schtasks /Change /TN "{task_path}" /Enable')
        if not cmd_result['success']:
            log_message(f"Failed to enable task '{task_path}'. Error: {cmd_result['stderr']}")
            if ("Zugriff verweigert" in cmd_result['stderr'] or "Access is denied" in cmd_result['stderr'].lower()) and not admin_warning_shown:
                messagebox.showwarning("Task Error", f"Access denied for task: {task_path}.\nEnsure script is run as Administrator.")
                admin_warning_shown = True
            overall_success = False
        else:
            log_message(f"Successfully enabled task '{task_path}'.")
    return overall_success

# ---------------------------
# Firewall Rules Tweak
# ---------------------------
def apply_fw_block():
    log_message(f"Attempting to apply firewall block rule: {FW_RULE_NAME}")
    resolved_ip_list_str = resolve_hostnames_to_ips(FW_HOSTNAMES_TO_BLOCK)
    if not resolved_ip_list_str:
        log_message("Firewall rule not applied: No IPs could be resolved from the hostnames.")
        messagebox.showerror("Firewall Error", "Could not resolve any hostnames to IP addresses. Firewall rule not applied. Check DNS and internet connectivity.")
        return False

    log_message(f"Resolved IPs for firewall rule '{FW_RULE_NAME}': {resolved_ip_list_str}")

    delete_cmd = f'netsh advfirewall firewall delete rule name="{FW_RULE_NAME}"'
    log_message(f"Attempting to delete existing rule (if any): {delete_cmd}")
    run_cmd(delete_cmd) 
    
    add_cmd = f'netsh advfirewall firewall add rule name="{FW_RULE_NAME}" dir=out action=block remoteip="{resolved_ip_list_str}" enable=yes profile=any'
    cmd_result = run_cmd(add_cmd)
    if not cmd_result['success']:
        log_message(f"Failed to add firewall rule '{FW_RULE_NAME}'. Error: {cmd_result['stderr']}. Stdout: {cmd_result['stdout']}")
        messagebox.showerror("Firewall Error", f"Failed to add firewall rule '{FW_RULE_NAME}'.\nError: {cmd_result['stderr'] or cmd_result['stdout']}. Check logs.")
        return False
    log_message(f"Successfully added/updated firewall rule '{FW_RULE_NAME}'.")
    return True

def undo_fw_block():
    log_message(f"Attempting to undo firewall block rule: {FW_RULE_NAME}")
    delete_cmd = f'netsh advfirewall firewall delete rule name="{FW_RULE_NAME}"'
    cmd_result = run_cmd(delete_cmd)
    if not cmd_result['success']:
        if "No rules match the specified criteria" in cmd_result['stdout'] or "No rules match the specified criteria" in cmd_result['stderr'] or \
           "Keine Regeln stimmen mit den angegebenen Kriterien überein" in cmd_result['stdout'] or \
           "Keine Regeln stimmen mit den angegebenen Kriterien überein" in cmd_result['stderr']:
            log_message(f"Firewall rule '{FW_RULE_NAME}' did not exist, so no action taken for undo.")
            return True 
        log_message(f"Failed to delete firewall rule '{FW_RULE_NAME}'. Error: {cmd_result['stderr']}")
        return False
    log_message(f"Successfully deleted firewall rule '{FW_RULE_NAME}'.")
    return True

# ---------------------------
# Other Tweaks: Services, Hosts, GPO
# ---------------------------
def get_service_status(name):
    log_message(f"Getting service status for {name}")
    try:
        cmd_result = run_cmd(f"sc query {name}")
        if cmd_result['success']:
            state = "Unknown"
            for l in cmd_result['stdout'].splitlines():
                if "STATE" in l:
                    state_parts = l.split()
                    if len(state_parts) > 3: state = state_parts[3] 
                    break
            key_path = f"SYSTEM\\CurrentControlSet\\Services\\{name}"
            start_type = "Unknown"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    start_val = winreg.QueryValueEx(key, "Start")[0]
                    if start_val == 2: start_type = "Automatic"
                    elif start_val == 3: start_type = "Manual"
                    elif start_val == 4: start_type = "Disabled"
            except FileNotFoundError:
                log_message(f"Registry key for service {name} start type not found.")
            except Exception as e_reg:
                log_message(f"Error reading service {name} start type from registry: {e_reg}")

            if state == "RUNNING": return "Running"
            if start_type == "Disabled": return "Disabled"
            if state == "STOPPED": return "Stopped"
            return f"{state} ({start_type})"
        else:
            log_message(f"Failed to query service {name}: {cmd_result['stderr']}")
            if "does not exist" in cmd_result['stderr'].lower() or "nicht vorhanden" in cmd_result['stderr'].lower():
                return "Missing"
            return "Unknown"
    except Exception as e:
        log_message(f"Exception getting service status for {name}: {e}")
        return "Unknown"

def disable_service(name):
    log_message(f"Disabling service: {name}")
    run_cmd(f"sc stop {name}") 
    return run_cmd(f"sc config {name} start= disabled")['success']

def enable_service(name):
    log_message(f"Enabling service: {name} (to Manual/Demand Start)")
    return run_cmd(f"sc config {name} start= demand")['success']

def apply_hosts_block():
    log_message("Applying hosts block...")
    try:
        with open(HOSTS_PATH, 'r+', encoding='utf-8', errors='ignore') as f:
            data = f.read()
            f.seek(0, os.SEEK_END)
            if data and not data.endswith('\n'): f.write('\n')
            for e in HOSTS_ENTRIES:
                if e not in data:
                    f.write(e + '\n')
        log_message("Hosts block applied.")
        return True
    except Exception as e:
        log_message(f"Failed to apply hosts block: {e}")
        return False

def undo_hosts_block():
    log_message("Undoing hosts block...")
    try:
        lines = []
        with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f: lines = f.readlines()
        with open(HOSTS_PATH, 'w', encoding='utf-8', errors='ignore') as f:
            for l in lines:
                if not any(e in l for e in HOSTS_ENTRIES):
                    f.write(l)
        log_message("Hosts block undone.")
        return True
    except Exception as e:
        log_message(f"Failed to undo hosts block: {e}")
        return False

def get_hosts_status():
    log_message("Getting hosts status...")
    try:
        with open(HOSTS_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            data = f.read()
        if all(e in data for e in HOSTS_ENTRIES):
            return "Blocked"
        else:
            return "Unblocked"
    except Exception as e:
        log_message(f"Error getting hosts status: {e}")
        return "Unknown"

def set_registry(path, name, value):
    log_message(f"Setting registry: HKLM\\{path}, Name='{name}', Value='{value}'")
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        log_message("Registry set successfully.")
        return True
    except Exception as e:
        log_message(f"Failed to set registry: {e}")
        return False

def get_registry_status(): 
    log_message("Getting NoAutoUpdate registry status...")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU") as key:
            val = winreg.QueryValueEx(key, "NoAutoUpdate")[0]
        return "Disabled" if val == 1 else "Enabled"
    except FileNotFoundError:
        log_message("NoAutoUpdate key or value not found, assuming Enabled.")
        return "Enabled"
    except Exception as e:
        log_message(f"Error getting NoAutoUpdate registry status: {e}")
        return "Unknown"

def apply_gpo_disable(): 
    return set_registry(
        r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "DisableWindowsUpdateAccess", 1
    )

def undo_gpo_disable():
    return set_registry(
        r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "DisableWindowsUpdateAccess", 0
    )

def get_gpo_status(): 
    log_message("Getting DisableWindowsUpdateAccess GPO status...")
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        ) as key:
            val = winreg.QueryValueEx(key, "DisableWindowsUpdateAccess")[0]
        return "Disabled" if val == 1 else "Enabled"
    except FileNotFoundError:
        log_message("DisableWindowsUpdateAccess key or value not found, assuming Enabled.")
        return "Enabled"
    except Exception as e:
        log_message(f"Error getting GPO status: {e}")
        return "Unknown"

# ---------------------------
# UI Helpers
# ---------------------------
def status_color(s):
    return {
        "Running": "green", "Stopped": "orange", "Disabled": "red",
        "Blocked": "red", "Unblocked": "green",
        "Enabled": "green", "Unknown": "gray", "Missing": "gray",
        "Locked": "red", "Writable": "green", "Renamed": "orange",
        "Ready": "green", "Mixed": "orange"
    }.get(s, "gray")

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget; self.text = text; self.tip = None
        widget.bind("<Enter>", self.show); widget.bind("<Leave>", self.hide)
    def show(self, event=None):
        if self.tip or not self.text: return
        x = event.x_root+10 if event else self.widget.winfo_rootx()+10
        y = event.y_root+10 if event else self.widget.winfo_rooty()+10
        self.tip = tw = tk.Toplevel(self.widget); tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(tw, text=self.text, bg="#333", fg="#fff",
                       font=("Segoe UI", 9), bd=1, relief=tk.SOLID)
        lbl.pack(ipadx=5, ipady=3)
    def hide(self, event=None):
        if self.tip: self.tip.destroy(); self.tip = None

# ---------------------------
# Main GUI
# ---------------------------
TWEAKS = [
    {"name":"Windows Update Service",   "apply":lambda: disable_service("wuauserv"), "undo":lambda: enable_service("wuauserv"), "status":lambda: get_service_status("wuauserv"), "info":"Stop & disable wuauserv (set to Disabled)"},
    {"name":"Update Medic Service",     "apply":lambda: disable_service("WaaSMedicSvc"), "undo":lambda: enable_service("WaaSMedicSvc"), "status":lambda: get_service_status("WaaSMedicSvc"), "info":"Stop & disable WaaSMedicSvc (set to Disabled)"},
    {"name":"Orchestrator Service",     "apply":lambda: disable_service("UsoSvc"), "undo":lambda: enable_service("UsoSvc"), "status":lambda: get_service_status("UsoSvc"), "info":"Stop & disable UsoSvc (set to Disabled)"},
    {"name":"Hosts Block",              "apply":apply_hosts_block, "undo":undo_hosts_block, "status":get_hosts_status, "info":"Block update domains via hosts file"},
    {"name":"Auto Updates Reg",         "apply":lambda:set_registry(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate",1), "undo":lambda:set_registry(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate",0), "status":get_registry_status, "info":"Set NoAutoUpdate=1 via registry"},
    {"name":"GPO Disable Access",       "apply":apply_gpo_disable,"undo":undo_gpo_disable,"status":get_gpo_status,"info":"Set DisableWindowsUpdateAccess=1 via GPO policy"},
    {"name":"Lock wuauclt.exe (ACL)",   "apply":apply_file_lock_revised,"undo":undo_file_lock_revised,"status":get_file_status,"info":"Deny Everyone Write on wuauclt.exe (Mutex with Rename)"},
    {"name":"Rename wuauclt.exe",       "apply":apply_file_rename_revised,"undo":undo_file_rename_revised,"status":get_file_status,"info":"Rename wuauclt.exe to .bak (Mutex with Lock)"},
    {"name":"Scheduled Tasks",          "apply":apply_tasks_disable,"undo":undo_tasks_disable,"status":get_tasks_status,"info":"Disable common Windows Update scheduled tasks. Requires Admin. Some tasks may be SYSTEM protected."},
    {"name":"Firewall Block (Out)",     "apply":apply_fw_block,"undo":undo_fw_block,"status":get_fw_status,"info":f"Block resolved IPs of update domains via Firewall. Requires Admin & Internet for DNS."},
]

root = tk.Tk()
root.title("🔥 Windows Update Tweaker v1.0 (Status Fixes) 🔥")
root.geometry("860x750") 
root.configure(bg="#f0f0f0")

font_hdr = ("Segoe UI", 16, "bold")
font_def = ("Segoe UI", 11)
font_bld = ("Segoe UI", 10, "bold")

tk.Label(root, text="Windows Update Tweaker v1.0", font=font_hdr, bg="#f0f0f0").pack(pady=15)

status_labels = []

def refresh_all_statuses():
    log_message("--- Refreshing all statuses ---")
    for lbl, tw_data in status_labels:
        st_val = tw_data['status']()
        lbl.config(text=st_val, fg=status_color(st_val))
    log_message("--- Status refresh complete ---")

for tweak_item in TWEAKS:
    frame = tk.Frame(root, bg="#fff", bd=1, relief=tk.SOLID, padx=10, pady=10)
    frame.pack(fill=tk.X, padx=20, pady=5)
    tk.Label(frame, text=tweak_item['name'], font=font_def, bg="#fff", wraplength=300, justify=tk.LEFT).pack(side=tk.LEFT, anchor="w")
    
    current_status_val = tweak_item['status']()
    status_label_widget = tk.Label(frame, text=current_status_val, font=font_def, fg=status_color(current_status_val), bg="#fff", width=15, anchor="e")
    status_label_widget.pack(side=tk.RIGHT, padx=(0,5))
    status_labels.append((status_label_widget, tweak_item))
    
    apply_button = tk.Button(frame, text="Apply", font=font_bld, bg="#4CAF50", fg="#fff", activebackground="#45a049", width=8)
    undo_button = tk.Button(frame, text="Undo", font=font_bld, bg="#f44336", fg="#fff", activebackground="#da190b", width=8)
    apply_button.pack(side=tk.RIGHT, padx=5)
    undo_button.pack(side=tk.RIGHT, padx=(0,5))
    
    ToolTip(apply_button, tweak_item['info'])
    ToolTip(undo_button, f"Revert: {tweak_item['info']}")

    def create_action_handler(tw, lbl):
        def do_apply_action(): 
            log_message(f"--- Applying tweak: {tw['name']} ---")
            op_ok = tw['apply']()
            new_st = tw['status']()
            lbl.config(text=new_st, fg=status_color(new_st))
            result_msg = "applied" if op_ok else "failed"
            log_message(f"Tweak '{tw['name']}' {result_msg}.")
            if op_ok and not isinstance(op_ok, str): 
                 messagebox.showinfo("Applied", f"{tw['name']} {result_msg}.")
            elif not op_ok : 
                if not (tw['name'] == "Firewall Block (Out)" or tw['name'] == "Scheduled Tasks"): 
                    messagebox.showerror("Error", f"Failed to apply {tw['name']}. Check logs for details.")
        
        def do_undo_action(): 
            log_message(f"--- Undoing tweak: {tw['name']} ---")
            op_ok = tw['undo']()
            new_st = tw['status']()
            lbl.config(text=new_st, fg=status_color(new_st))
            result_msg = "reverted" if op_ok else "failed"
            log_message(f"Tweak '{tw['name']}' {result_msg}.")
            if op_ok and not isinstance(op_ok, str):
                messagebox.showinfo("Reverted", f"{tw['name']} {result_msg}.")
            elif not op_ok: 
                messagebox.showerror("Error", f"Failed to revert {tw['name']}. Check logs for details.")
        return do_apply_action, do_undo_action

    apply_action, undo_action = create_action_handler(tweak_item, status_label_widget)
    apply_button.config(command=apply_action)
    undo_button.config(command=undo_action)

bottom_frame = tk.Frame(root, bg="#f0f0f0")
bottom_frame.pack(fill=tk.X, pady=15, padx=20)
refresh_button = tk.Button(bottom_frame, text="Refresh All Statuses", font=font_bld, bg="#2196F3", fg="#fff", command=refresh_all_statuses)
about_button = tk.Button(bottom_frame, text="About", font=font_bld, bg="#555", fg="#fff", command=lambda: messagebox.showinfo("About", "Windows Update Tweaker v1.0\nStatus Detection Fixes\nLogs to tweak_log.txt"))
exit_button = tk.Button(bottom_frame, text="Exit", font=font_bld, bg="#777", fg="#fff", command=root.destroy)
refresh_button.pack(side=tk.LEFT, padx=10)
about_button.pack(side=tk.LEFT)
exit_button.pack(side=tk.RIGHT, padx=10)

log_message("--- GUI initialized ---")
refresh_all_statuses() 
root.mainloop()
log_message("--- Script finished ---")

