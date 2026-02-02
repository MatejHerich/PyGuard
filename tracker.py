import os
import time
import threading
import psutil
import shutil
import hashlib
import requests
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv()

SUSPICIOUS_PATHS = ("downloads", "temp", "tmp", "appdata\\local\\temp", "%temp%")
_QUARANTINE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PyGuard_Quarantine")
_DOWNLOADS_DIR = os.path.expanduser("~\\Downloads")

# LOLBAS - Living-off-the-Land Binaries (legitimne nástroje zneužívané na útok)
LOLBAS_TOOLS = (
    "powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe", 
    "wmic.exe", "schtasks.exe", "regsvcs.exe", "rundll32.exe",
    "cscript.exe", "wscript.exe", "mshta.exe", "regsvr32.exe",
    "cmstp.exe", "msiexec.exe", "odbcconf.exe", "mavinject.exe"
)

# Kritické systémové priečinky
CRITICAL_SYSTEM_PATHS = (
    "windows\\system32",
    "windows\\syswow64",
    "programfiles",
    "program files (x86)",
    "windows\\temp",
    "windows\\prefetch"
)

def get_downloads_dir():
    """Vráti cestu do Downloads priečinka."""
    if os.path.exists(_DOWNLOADS_DIR):
        return _DOWNLOADS_DIR
    return None

def ensure_quarantine_dir():
    """Zabezpečí, že existuje priečinok karantény."""
    if not os.path.exists(_QUARANTINE_DEFAULT):
        os.makedirs(_QUARANTINE_DEFAULT)

def show_process_alert(exe, pid, name):
    """Zobrazí vyskakovacie okno s výzvou na premiestnenie procesu do karantény."""
    root = tk.Tk()
    root.withdraw()  # Skryje hlavné okno
    root.attributes('-topmost', True)  # Okno vždy navrchu
    
    message = f"🚨 PODOZRIVÝ PROCES ZISTENÝ!\n\n" \
              f"Proces: {name}\n" \
              f"PID: {pid}\n" \
              f"Cesta: {exe or 'Neznáma'}\n\n" \
              f"Chceš presunúť tento proces do karantény?"
    
    result = messagebox.askyesno("PyGuard - Podozrivý proces", message)
    root.destroy()
    
    return result

def _path_suspicious(path):
    if not path:
        return False
    p = os.path.normpath(path).lower()
    return any(s in p for s in SUSPICIOUS_PATHS)

def calculate_entropy(data):
    """Vypočíta Shannon entropy - meradlo randomnosti/kompresie v dátach."""
    if not data:
        return 0
    
    # Počet výskytov každého bytu
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Výpočet entropie
    entropy = 0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * (probability ** 0.5)  # Zjednodušená Shannon entropy
    
    return entropy

def is_entropy_suspicious(filepath):
    """
    Detekuje zabaľované/zašifrované súbory.
    Vysoká entropia = pravdepodobne zabaľované malware.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(65536)  # Prvých 64KB
        
        entropy = calculate_entropy(data)
        # Vysoká entropia (>7.5) ukazuje na compression/encryption
        return entropy > 7.5
    except Exception:
        return False

def is_file_in_critical_path(filepath):
    """Skontroluje či je súbor v kritických systémových priečinkoch."""
    if not filepath:
        return False
    p = os.path.normpath(filepath).lower()
    return any(critical in p for critical in CRITICAL_SYSTEM_PATHS)

def is_lolbas_suspicious(process_name, parent_name, has_network, exe):
    """
    Detekuje podozrivé používanie LOLBAS nástrojov.
    Napríklad: cmd.exe s network aktivitou z Downloads.
    """
    if process_name.lower() not in LOLBAS_TOOLS:
        return False
    
    # LOLBAS je podozrivý ak:
    # 1. Má networkové spojenie
    # 2. Je spustený z podozrivej lokácie
    # 3. Je spustený bez interakcie s používateľom (parent != explorer.exe)
    
    is_network_suspicious = has_network
    is_path_suspicious = is_file_in_critical_path(exe) or _path_suspicious(exe)
    is_parent_suspicious = parent_name and parent_name.lower() not in ("explorer.exe", "svchost.exe", "services.exe")
    
    return is_network_suspicious or (is_path_suspicious and is_parent_suspicious)

def get_process_network_details(pid):
    """Vracia detailne info o network spojeniach procesu."""
    try:
        proc = psutil.Process(pid)
        connections = proc.connections()
        
        details = []
        for conn in connections:
            remote_ip = conn.raddr[0] if conn.raddr else "Unknown"
            remote_port = conn.raddr[1] if conn.raddr else "Unknown"
            status = conn.status
            
            # Ak sa pripája na podozrivé miesta (nie localhost, nie corporate sieť)
            if remote_ip not in ("127.0.0.1", "::1") and not remote_ip.startswith("192.168.") and not remote_ip.startswith("10."):
                details.append({
                    "ip": remote_ip,
                    "port": remote_port,
                    "status": status
                })
        return details
    except Exception:
        return []

def is_behavioral_suspicious(pid, exe, name, cwd, parent_name):
    """
    Heuristická detekcia anomálneho správania.
    Kombinuje viaceré indikátory na detekciu pôvodného malware správania.
    """
    score = 0
    
    # Indikátor 1: Spustenie z Downloads/Temp
    if _path_suspicious(exe) or _path_suspicious(cwd):
        score += 2
    
    # Indikátor 2: Spustenie z kritickej cesty bez proper parent
    if is_file_in_critical_path(exe) and parent_name not in ("services.exe", "svchost.exe", "system", "services"):
        score += 2
    
    # Indikátor 3: Double extension (napr. file.pdf.exe)
    if exe:
        name_lower = os.path.basename(exe).lower()
        # Detekuje双 extensions
        if name_lower.count(".") > 1:
            parts = name_lower.rsplit(".", 2)
            if parts[1] in ("pdf", "doc", "docx", "xls", "zip", "rar"):
                score += 3
    
    # Indikátor 4: Obfuscovaná mena (veľa číslic/náhodných znakov)
    if exe:
        base = os.path.basename(exe).lower()
        digit_ratio = sum(1 for c in base if c.isdigit()) / max(len(base), 1)
        if digit_ratio > 0.3:  # Viac ako 30% číslic
            score += 1
    
    # Indikátor 5: Proces bez popisu (malware sa často maskuje bez popisu)
    try:
        proc = psutil.Process(pid)
        if not proc.name() or proc.name() == "":
            score += 1
    except Exception:
        pass
    
    return score >= 3

def show_detailed_threat_alert(exe, pid, name, threat_type, details):
    """Zobrazí detailné vyskakovacie okno s hrozbou."""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    detail_str = ""
    if threat_type == "entropy" and isinstance(details, float):
        detail_str = f"Typ hrozby: ZABAĽOVANÉ MALWARE (Entropy: {details:.2f})\n"
    elif threat_type == "behavioral":
        detail_str = f"Typ hrozby: ANOMÁLNE SPRÁVANIE\n"
    elif threat_type == "lolbas":
        detail_str = f"Typ hrozby: ZNEUŽÍVANIE SYSTÉMOVÉHO NÁSTROJA (LOLBAS)\n"
    elif threat_type == "network":
        detail_str = f"Typ hrozby: PODOZRIVÁ SIEŤOVÁ AKTIVITA\n"
        if isinstance(details, list) and details:
            for conn in details[:3]:
                detail_str += f"  • Spojenie na: {conn['ip']}:{conn['port']}\n"
    elif threat_type == "critical_path":
        detail_str = f"Typ hrozby: SPUSTENIE V KRITICKEJ CESTE\n"
    
    message = f"🚨 VYSOKÁ HROZBA!\n\n" \
              f"Proces: {name}\n" \
              f"PID: {pid}\n" \
              f"Cesta: {exe or 'Neznáma'}\n\n" \
              f"{detail_str}\n" \
              f"Chceš OKAMŽITE presunúť do karantény?"
    
    result = messagebox.askyesno("PyGuard ⚠️ KRITICKÁ HROZBA", message)
    root.destroy()
    
    return result

class DownloadMonitor(FileSystemEventHandler):
    """Sleduje nové stahovávané súbory v Downloads priečinku."""
    
    def on_created(self, event):
        """Spustí sa keď sa vytvorí nový súbor."""
        if event.is_directory:
            return
        
        filepath = event.src_path
        # Pockaj, kým sa súbor úplne stiahne
        time.sleep(2)
        
        if not os.path.exists(filepath):
            return
        
        try:
            # Preskakuj malé súbory (napr. .tmp, .tmp.part súbory)
            if os.path.getsize(filepath) < 1024:  # Menej ako 1KB
                return
            
            filename = os.path.basename(filepath)
            
            # Kontrola 1: Entropy analýza
            if is_entropy_suspicious(filepath):
                if show_file_alert(filename, filepath, [{"malware_family": "Zabaľovaný/zašifrovaný súbor"}]):
                    try:
                        os.makedirs(_QUARANTINE_DEFAULT, exist_ok=True)
                        quarantine_path = os.path.join(_QUARANTINE_DEFAULT, filename)
                        if os.path.exists(quarantine_path):
                            name, ext = os.path.splitext(filename)
                            quarantine_path = os.path.join(_QUARANTINE_DEFAULT, f"{name}_{int(time.time())}{ext}")
                        shutil.move(filepath, quarantine_path)
                    except Exception as e:
                        pass
                return
            
            # Vypočítaj SHA-256 hash
            file_hash = calculate_sha256(filepath)
            if not file_hash:
                return
            
            # Skontroluj hash v MalwareBazaar
            hash_result = check_hash_malwarebazaar(file_hash)
            
            if hash_result is not None:
                # Zobrazí okno s výzvou
                if show_file_alert(filename, filepath, hash_result):
                    # Ak používateľ klikne "Áno", presúň do karantény
                    try:
                        os.makedirs(_QUARANTINE_DEFAULT, exist_ok=True)
                        quarantine_path = os.path.join(_QUARANTINE_DEFAULT, filename)
                        if os.path.exists(quarantine_path):
                            name, ext = os.path.splitext(filename)
                            quarantine_path = os.path.join(_QUARANTINE_DEFAULT, f"{name}_{int(time.time())}{ext}")
                        shutil.move(filepath, quarantine_path)
                    except Exception as e:
                        pass
        except Exception as e:
            pass

def quarantine_process_executable(exe):
    """Presúva spustiteľný súbor do karantény."""
    try:
        ensure_quarantine_dir()
        if exe and os.path.exists(exe):
            filename = os.path.basename(exe)
            quarantine_path = os.path.join(_QUARANTINE_DEFAULT, filename)
            
            # Ak súbor už existuje, pridaj timestamp
            if os.path.exists(quarantine_path):
                name, ext = os.path.splitext(filename)
                timestamp = int(time.time())
                filename = f"{name}_{timestamp}{ext}"
                quarantine_path = os.path.join(_QUARANTINE_DEFAULT, filename)
            
            shutil.move(exe, quarantine_path)
            return True
    except Exception as e:
        return False

def calculate_sha256(filepath):
    """Vypočíta SHA-256 hash súboru."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None

def check_hash_malwarebazaar(sha256_hash):
    """
    Skontroluje SHA-256 hash v databáze MalwareBazaar (abuse.ch).
    Vyžaduje voľný API kľúč v premennej ABUSE_CH_API_KEY.
    """
    api_key = os.environ.get("ABUSE_CH_API_KEY")
    if not api_key:
        return None  # API kľúč nie je nastavený

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": api_key}
    data = {"query": "get_info", "hash": sha256_hash}

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=15)
        resp.raise_for_status()
        j = resp.json()
        if j.get("query_status") == "ok" and j.get("data"):
            return j["data"]  # zoznam záznamov (môže byť viac)
        return []  # hash nie je v databáze
    except requests.RequestException as e:
        return None

def show_file_alert(filename, filepath, hash_result):
    """Zobrazí vyskakovacie okno s informáciami o stahovenom súbore."""
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    threat_info = ""
    if hash_result and len(hash_result) > 0:
        threat_info = "⚠️ HROZBA ZISTENÁ!\n\n"
        if isinstance(hash_result, list) and len(hash_result) > 0:
            for item in hash_result[:2]:  # Ukaž maximálne 2 výsledky
                if isinstance(item, dict):
                    family = item.get("malware_family", "Neznáma")
                    threat_info += f"Typ hrozby: {family}\n"
    else:
        threat_info = "✅ Súbor pravdepodobne bezpečný\n"
    
    message = f"📥 NOV STIAHNUTÝ SÚBOR\n\n" \
              f"Meno: {filename}\n" \
              f"Cesta: {filepath}\n\n" \
              f"{threat_info}\n" \
              f"Chceš presunúť súbor do karantény?"
    
    if hash_result and len(hash_result) > 0:
        result = messagebox.askyesno("PyGuard - Podozrivý súbor", message)
        return result
    else:
        messagebox.showinfo("PyGuard - Informácia", message)
        return False

def loop():
    # Spustí monitoring Downloads priečinka
    downloads_dir = get_downloads_dir()
    observer = None
    
    if downloads_dir:
        event_handler = DownloadMonitor()
        observer = Observer()
        observer.schedule(event_handler, downloads_dir, recursive=True)
        observer.start()
    
    reported_pids = set()  # Zabránenie viacnásobným alertom na ten istý proces
    
    while True:
        try:
            for proc in psutil.process_iter(["pid", "exe", "name", "cmdline"]):
                try:
                    pinfo = proc.info
                    pid = pinfo.get("pid")
                    exe = pinfo.get("exe")
                    name = pinfo.get("name")
                    cmdline = pinfo.get("cmdline") or []

                    cwd = None
                    try:
                        cwd = proc.cwd()
                    except (psutil.AccessDenied, OSError):
                        pass

                    parent = None
                    parent_name = None
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    connections = []
                    try:
                        connections = proc.connections()
                    except (psutil.AccessDenied, OSError):
                        pass

                    has_network = len(connections) > 0
                    
                    # ===== DETEKCIA 1: Kritická systémová cesta =====
                    if is_file_in_critical_path(exe) and pid not in reported_pids:
                        if show_detailed_threat_alert(exe, pid, name, "critical_path", None):
                            if quarantine_process_executable(exe):
                                try:
                                    proc.kill()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            reported_pids.add(pid)
                            continue
                    
                    # ===== DETEKCIA 2: LOLBAS (Living-off-the-Land Binaries) =====
                    if is_lolbas_suspicious(name, parent_name, has_network, exe) and pid not in reported_pids:
                        if show_detailed_threat_alert(exe, pid, name, "lolbas", None):
                            if quarantine_process_executable(exe):
                                try:
                                    proc.kill()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            reported_pids.add(pid)
                            continue
                    
                    # ===== DETEKCIA 3: Podozrivá sieťová aktivita =====
                    if has_network and pid not in reported_pids:
                        network_details = get_process_network_details(pid)
                        if network_details and _path_suspicious(exe):  # Len ak je z podozrivej cesty
                            if show_detailed_threat_alert(exe, pid, name, "network", network_details):
                                if quarantine_process_executable(exe):
                                    try:
                                        proc.kill()
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        pass
                                reported_pids.add(pid)
                                continue
                    
                    # ===== DETEKCIA 4: Behavioral (anomálne správanie) =====
                    if is_behavioral_suspicious(pid, exe, name, cwd, parent_name) and pid not in reported_pids:
                        if show_detailed_threat_alert(exe, pid, name, "behavioral", None):
                            if quarantine_process_executable(exe):
                                try:
                                    proc.kill()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            reported_pids.add(pid)
                            continue
                    
                    # ===== DETEKCIA 5: Původná detekcia (Downloads/Temp) =====
                    exe_suspicious = _path_suspicious(exe)
                    cwd_suspicious = _path_suspicious(cwd)
                    parent_suspicious = parent_name in ("cmd.exe", "powershell.exe") if parent_name else False

                    if (exe_suspicious or cwd_suspicious or (has_network and parent_suspicious)) and pid not in reported_pids:
                        if show_process_alert(exe, pid, name):
                            if quarantine_process_executable(exe):
                                try:
                                    proc.kill()
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                                reported_pids.add(pid)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        
        # Vyčisti zastarané PID z pamäte (procesy ktoré už neexistujú)
        to_remove = set()
        for reported_pid in reported_pids:
            try:
                psutil.Process(reported_pid)
            except psutil.NoSuchProcess:
                to_remove.add(reported_pid)
        reported_pids -= to_remove
        
        time.sleep(30)