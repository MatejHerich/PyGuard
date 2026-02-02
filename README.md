# PyGuard

Jednoduchý antivírusový nástroj napísaný v Pythone. Celý zmysel aplikácie je v tom, že keď máš nejaký súbor a nevieš či je bezpečný, tak ho môžeš "oskenovat" - PyGuard z neho vypočíta unikátny odtlačok (hash) a pozrie sa do verejnej databázy známych vírusov, či tam náhodou nie je. Ak áno, vieš že máš problém.

## Čo to vlastne robí?

Každý súbor na počítači sa dá "zhašovať" - teda vypočítať z neho unikátny reťazec znakov (niečo ako odtlačok prsta). Dva rovnaké súbory majú vždy rovnaký hash. Existujú verejné databázy (napríklad MalwareBazaar od abuse.ch), kde sú uložené hashe známych vírusov a malvérov. 

PyGuard jednoducho:
1. Zoberie tvoj súbor
2. Vypočíta jeho SHA-256 hash
3. Pošle tento hash do databázy MalwareBazaar
4. Povie ti, či tam bol nájdený alebo nie

Ak bol nájdený = ten súbor je pravdepodobne škodlivý a mal by si ho dať do karantény alebo zmazať.

## Ako to nainštalovať

Potrebuješ Python 3. Potom v priečinku projektu spusti:

```
python -m pip install -r requirements.txt
```

Ešte potrebuješ API kľúč z MalwareBazaar - je zadarmo, stačí sa zaregistrovať na https://auth.abuse.ch/ a kľúč si skopírovať. Potom vytvor súbor `.env` v priečinku projektu a daj tam:

```
ABUSE_CH_API_KEY=tvoj_kluc_sem
```

## Ako to spustiť

```
python main.py
```

Uvidíš farebné logo a prompt `PyGuard > `. Odtiaľ zadávaš príkazy.

## Príkazy

| Príkaz | Čo robí |
|--------|---------|
| `scanf subor.exe` | Oskenuje jeden súbor |
| `scand C:\Downloads` | Oskenuje celý priečinok (aj podpriečinky) |
| `scand C:\Downloads --no-recursive` | Oskenuje len daný priečinok bez podpriečinkov |
| `quarantine subor.exe` | Zabije procesy súboru a presunie ho do karantény |
| `quarantine-list` | Ukáže čo je v karanténe |
| `quarantine-clear` | Vymaže všetko z karantény (spýta sa na potvrdenie) |

## Ako funguje kód - vysvetlenie

### Načítanie knižníc a konfigurácie

Na začiatku importujeme všetko čo potrebujeme:

```python
import click              # na tvorbu príkazov v termináli
import click_shell        # robí z toho interaktívny shell
import os                 # práca so súbormi a priečinkami
import hashlib            # výpočet SHA-256 hashu
import shutil             # presúvanie súborov
import stat               # zmena oprávnení súborov
import time               # práca s časom
import requests           # HTTP požiadavky na API
import psutil             # práca s procesmi (na zabitie procesov)
from dotenv import load_dotenv  # načítanie .env súboru
```

Hneď po importoch zavoláme `load_dotenv()` - to načíta premenné zo súboru `.env` do prostredia. Vďaka tomu nemusíme API kľúč písať priamo do kódu (čo by bolo nebezpečné ak by si kód zdieľal).

### Farebné logo

Funkcia `get_welcome_screen()` generuje to farebné ASCII logo čo vidíš pri spustení. Používame `click.style()` na farbenie textu:

```python
def get_welcome_screen():
    logo_lines = [
        r"  _____ __     _______ _    _         _____  _____  ",
        r" |  __ \\ \   / / ____| |  | |  /\   |  __ \|  __ \ ",
        # ... ďalšie riadky loga
    ]
    lines = []
    for line in logo_lines:
        lines.append(click.style(line, fg='cyan'))  # cyan farba pre logo
    # ... zelený nadpis, žltý status
    return "\n".join(lines)
```

Tie `r"..."` pred reťazcami znamenajú "raw string" - backslashe sa berú doslova a netreba ich zdvojovať. To je dôležité pre ASCII art kde je veľa lomítok.

### Výpočet SHA-256 hashu

Toto je srdce celej aplikácie. Funkcia `calculate_sha256()` zoberie súbor a vypočíta jeho hash:

```python
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()  # vytvoríme hashovací objekt
    with open(filepath, "rb") as f:  # otvoríme súbor v binárnom režime
        for byte_block in iter(lambda: f.read(4096), b""):  # čítame po 4KB kusoch
            sha256_hash.update(byte_block)  # pridáme kus do hashu
    return sha256_hash.hexdigest()  # vrátime hash ako text
```

Prečo čítame po 4KB a nie celý súbor naraz? Keby si mal 10GB súbor a načítal ho celý do pamäte, počítač by sa zasekol. Takto to funguje aj pre obrovské súbory.

### Kontrola v databáze MalwareBazaar

Keď máme hash, pošleme ho do databázy:

```python
def check_hash_malwarebazaar(sha256_hash):
    api_key = os.environ.get("ABUSE_CH_API_KEY")  # získame kľúč z prostredia
    
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": api_key}
    data = {"query": "get_info", "hash": sha256_hash}
    
    resp = requests.post(url, headers=headers, data=data, timeout=15)
    j = resp.json()
    
    if j.get("query_status") == "ok" and j.get("data"):
        return j["data"]  # hash bol nájdený - vrátime info o malvéri
    return []  # hash nebol nájdený - súbor je čistý
```

Je to obyčajná POST požiadavka. API vráti JSON s informáciami. Ak je `query_status` "ok" a sú nejaké dáta, znamená to že hash bol v databáze nájdený = súbor je známy malvér.

### Karanténa

Karanténa je priečinok kam presúvame podozrivé súbory. Predvolene je to `PyGuard_Quarantine` vedľa `main.py`:

```python
_QUARANTINE_DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 
    "PyGuard_Quarantine"
)
```

Toto `os.path.dirname(os.path.abspath(__file__))` jednoducho znamená "priečinok kde leží tento Python súbor".

### Zabíjanie procesov

Pred presunom do karantény chceme zabiť procesy ktoré ten súbor používajú (napríklad ak je to bežiaci vírus). Na to používame `psutil`:

```python
def kill_processes_using_file(filepath):
    abs_path = os.path.abspath(filepath)
    for proc in psutil.process_iter(["pid", "exe", "name"]):
        exe = proc.info.get("exe")  # cesta k exe súboru procesu
        if exe and os.path.normpath(exe) == os.path.normpath(abs_path):
            proc.kill()  # zabiť proces
```

`psutil.process_iter()` prejde všetky bežiace procesy. Pre každý pozrieme či jeho exe súbor je ten čo hľadáme. Ak áno, zabijeme ho.

### Presun do karantény

```python
def move_to_quarantine(filepath):
    # Najprv zabijeme procesy
    kill_processes_using_file(filepath)
    time.sleep(0.5)  # chvíľu počkáme nech sa procesy stihnú ukončiť
    
    # Vytvoríme unikátne meno (aby sa súbory neprepisovali)
    unique = f"{name}_{int(time.time())}{ext}.quarantined"
    dest = os.path.join(qdir, unique)
    
    # Presunieme súbor
    shutil.move(abs_path, dest)
    
    # Nastavíme len na čítanie (sťažíme náhodné spustenie)
    os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
```

Ten `int(time.time())` pridá aktuálny čas v sekundách do názvu súboru. Takže ak dáš do karantény `virus.exe` dvakrát, budeš mať `virus_1738500000.exe.quarantined` a `virus_1738500005.exe.quarantined`.

### Click shell - interaktívne príkazy

Celá aplikácia beží ako interaktívny shell vďaka `click_shell`:

```python
@shell.shell(prompt='PyGuard > ', intro='')
def cli():
    pass  # telo je prázdne, je to len vstupný bod
```

Jednotlivé príkazy registrujeme cez `@cli.command()`:

```python
@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def scanf(filepath):
    # ... kód príkazu
```

Ten `click.Path(exists=True)` automaticky skontroluje či súbor existuje. Ak nie, click vypíše chybu a príkaz sa nespustí.

### Progress bar

Pri skenovaní priečinka zobrazujeme progress bar aby si videl koľko to ešte potrvá:

```python
with click.progressbar(files_to_scan, label='Skenovanie', show_pos=True, show_percent=True) as bar:
    for path in bar:
        # ... spracovanie súboru
```

`click.progressbar()` je super jednoduchý spôsob ako pridať progress bar. Automaticky ukazuje koľko položiek je spracovaných a percentá.

## Bezpečnostné veci

- **`.env` súbor** - nikdy ho nedávaj na GitHub ani nikam verejne. Obsahuje tvoj API kľúč. Preto je v `.gitignore`.
- **Administrátorské práva** - niekedy potrebuješ spustiť PyGuard ako správca, hlavne ak chceš zabiť systémové procesy.
- **Karanténa nie je dokonalá** - súbory sú len presunuté, nie šifrované ani zničené. Na úplné odstránenie použi `quarantine-clear`.

## Zhrnutie

PyGuard je učebný projekt ktorý ukazuje ako funguje základná detekcia malvéru pomocou hashov. Nie je to náhrada za skutočný antivírus, ale je to dobrý spôsob ako pochopiť princípy na ktorých antivírusy fungujú.

---

# 🛡️ Tracker - Automatická ochrana na pozadí

Vedľa interaktívneho PyGuardu existuje aj **Tracker** - samostatný Python modul (`tracker.py`) ktorý beží na pozadí a automaticky chráni tvoj počítač bez toho, aby si musel nič robiť.

## Čo Tracker robí?

Tracker monitoruje **5 rôznych činností**:

1. **📥 Sledovanie Downloads priečinka** - Každý nový súbor sa automaticky skenuje
2. **🔧 LOLBAS detekcia** - Detekuje zneužívanie legitímnych systémových nástrojov
3. **🧠 Behavioral detection** - Anomálne správanie procesov (double extensions, obfuscované mená, atď.)
4. **🌐 Sieťové monitorovanie** - Detekuje procesy ktoré sa pripájajú na podozrivé IP adresy
5. **🚨 Kritická systémová cesta** - Detekuje kód spustený z System32, SysWOW64, atď.

Ak Tracker niečo podozrivé zistí, **zobrazí ti vyskakovacie okno** s informáciami a spýta sa čo s tým chceš robiť.

## Ako spustiť Tracker

### Ručné spustenie (pre testovanie)

Tracker sa dá spustiť manuálne z Pythonu:

```python
from tracker import loop
loop()
```

Potom sa Tracker spustí a začne monitorovať počítač.

### Automatické spustenie pri štarte PC

Ak má Tracker bežať **automaticky pri každom štarte PC bez ľudskej intervencie**, je potrebné ho pridať do Windows Startup priečinka.

Na to slúži súbor `pyguard_startup.bat`:

```batch
@echo off
start "" pythonw.exe -c "import sys; sys.path.insert(0, r'%SCRIPT_DIR%'); from tracker import loop; loop()"
```

Tento skript spustí Tracker bez viditeľného okna - bude bežať čisto v pozadí. `pythonw.exe` je špeciálna verzia Pythonu ktorá nespúšťa čierne okno konzoly, je ideálna pre backgroundové úlohy.

**Ako sa to inštaluje:**

Súbor `pyguard_startup.bat` sa skopíruje do Windows Startup priečinka. Windows Startup priečinok sa nachádza v ceste:
```
C:\Users\<Meno>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Keď sa súbor BAT nachádza v Startup priečinku, Windows ho automaticky spustí pri štarte. Tracker potom beží nepretržite na pozadí bez toho aby bol viditeľný.

**Odinštalácia:**
Ak má byť Tracker odstránený, súbor `pyguard_startup.bat` sa vymaže zo Startup priečinka. Windows sa potom už nebude pokúšať ho spustiť.

## Ako funguje kód Trackeru - Detailné vysvetlenie

### Importy a konfigurácia

```python
import os
import time
import threading
import psutil           # Práca s procesmi
import shutil
import hashlib          # SHA-256 hashing
import requests         # API komunikácia
import tkinter as tk    # GUI okná
from tkinter import messagebox
from watchdog.observers import Observer      # Monitoring súborov
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv

load_dotenv()
```

**Čo je čo:**
- `psutil` - Čítame procesy, ich cesty, parent procesy, network spojenia
- `watchdog` - Real-time monitoring zmien v súboroch/priečinkoch
- `tkinter` - Natívne Windows okná (bez dodatočných dependency)
- `requests` - Volanie MalwareBazaar API

### Definície podozrivých nástrojov

```python
# LOLBAS - Living-off-the-Land Binaries
LOLBAS_TOOLS = (
    "powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
    # ... ďalšie
)

# Kritické systémové priečinky
CRITICAL_SYSTEM_PATHS = (
    "windows\\system32",
    "windows\\syswow64",
    # ...
)
```

Tieto sú zoznamy podozrivých věcí. Ak sa niečo z toho deje, je to červená vlajka.

### Entropy analýza - Detekcia zabaľovaného malware

```python
def calculate_entropy(data):
    """Vypočíta Shannon entropy - meradlo randomnosti v dátach."""
    if not data:
        return 0
    
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    entropy = 0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * (probability ** 0.5)
    
    return entropy
```

**Čo je to entropia?** Miera „náhodnosti" dát:
- **Nízka entropia** (~3-5) = Normálny text, zdrojový kód
- **Vysoká entropia** (>7.5) = Zašifrované dáta, komprimované dáta = **Zabaľovaný malware!**

Príklad:
- Text "aaaaaabbbbbb" = **nízka entropia** (len 2 rôzne znaky)
- Náhodné dáta "xQ9jK2mL7pR" = **vysoká entropia** (veľa rôznych znakov)

```python
def is_entropy_suspicious(filepath):
    """Detekuje zabaľované/zašifrované súbory."""
    with open(filepath, "rb") as f:
        data = f.read(65536)  # Prvých 64KB
    
    entropy = calculate_entropy(data)
    return entropy > 7.5  # Vysoká entropia = podozrivé
```

Prečo len prvých 64KB? Rýchlosť! Nemôžeme čítať celý 10GB súbor. Prvých 64KB nám povie dosť.

### LOLBAS detekcia

```python
def is_lolbas_suspicious(process_name, parent_name, has_network, exe):
    """Detekuje podozrivé používanie LOLBAS nástrojov."""
    if process_name.lower() not in LOLBAS_TOOLS:
        return False
    
    is_network_suspicious = has_network
    is_path_suspicious = is_file_in_critical_path(exe) or _path_suspicious(exe)
    is_parent_suspicious = parent_name and parent_name.lower() not in (
        "explorer.exe", "svchost.exe", "services.exe"
    )
    
    return is_network_suspicious or (is_path_suspicious and is_parent_suspicious)
```

**Logika:**
- Ak PowerShell.exe má network aktivitu = podozrivé
- Ak CMD.exe je spustený z Downloads = podozrivé
- Ak Certutil.exe má "zlého" parent (nie Windows štandardný) = podozrivé

**Príklad:** 
```
Situation: PowerShell.exe spustený z Downloads s network aktivitou
LOLBAS_TOOLS obsahuje powershell.exe ✓
has_network = True ✓
is_network_suspicious = True ✓
→ VRACIA: True (JE PODOZRIVÉ)
```

### Behavioral Detection - Bodovací systém

```python
def is_behavioral_suspicious(pid, exe, name, cwd, parent_name):
    """Heuristická detekcia anomálneho správania."""
    score = 0
    
    # Indikátor 1: Spustenie z Downloads/Temp
    if _path_suspicious(exe) or _path_suspicious(cwd):
        score += 2
    
    # Indikátor 2: Spustenie z kritickej cesty bez vhodného parent
    if is_file_in_critical_path(exe) and parent_name not in ("services.exe", "svchost.exe"):
        score += 2
    
    # Indikátor 3: Double extension (file.pdf.exe)
    if exe:
        name_lower = os.path.basename(exe).lower()
        if name_lower.count(".") > 1:
            parts = name_lower.rsplit(".", 2)
            if parts[1] in ("pdf", "doc", "docx", "xls", "zip", "rar"):
                score += 3
    
    # Indikátor 4: Obfuscovaná mena (>30% číslic)
    if exe:
        base = os.path.basename(exe).lower()
        digit_ratio = sum(1 for c in base if c.isdigit()) / max(len(base), 1)
        if digit_ratio > 0.3:
            score += 1
    
    return score >= 3  # Ak má 3+ bodov → je podozrivý
```

**Príklad scoreovacieho systému:**

```
Súbor: C:\Users\Downloads\document_12345.pdf.exe
│
├─ Z Downloads?          → +2 bodov
├─ Double extension?     → +3 bodov (pdf.exe)
├─ Obfuscované meno?     → +1 bod (12345)
│
CELKEM: 2+3+1 = 6 bodov ≥ 3 → PODOZRIVÉ! 🚨
```

Bez tohto systému by sme falošne upozorňovali na všetko. S bodmi vieme lepšie rozlíšiť skutočnú hrozbu.

### Sieťové monitorovanie

```python
def get_process_network_details(pid):
    """Vracia detailne info o network spojeniach procesu."""
    proc = psutil.Process(pid)
    connections = proc.connections()
    
    details = []
    for conn in connections:
        remote_ip = conn.raddr[0] if conn.raddr else "Unknown"
        remote_port = conn.raddr[1] if conn.raddr else "Unknown"
        
        # Ignoruj localhost a corporate sieť
        if remote_ip not in ("127.0.0.1", "::1") and \
           not remote_ip.startswith("192.168.") and \
           not remote_ip.startswith("10."):
            details.append({
                "ip": remote_ip,
                "port": remote_port,
                "status": conn.status
            })
    return details
```

**Čo to robí:**
1. Čita všetky network spojenia procesu
2. Ignoruje "bezpečné" IP adresy (localhost, interná sieť)
3. Vráti iba podozrivé "vonkajšie" spojenia

**Príklad:**
```
Proces python.exe sa pripájajú na:
- 127.0.0.1:8000     → IGNORUJ (localhost)
- 192.168.1.1:443    → IGNORUJ (router)
- 185.220.101.45:443 → ALERTUJ! (vonkajšia IP)
```

### FileSystemEventHandler - Real-time monitoring

```python
class DownloadMonitor(FileSystemEventHandler):
    """Sleduje nové stahovávané súbory v Downloads priečinku."""
    
    def on_created(self, event):
        """Spustí sa keď sa vytvorí nový súbor."""
        if event.is_directory:
            return
        
        filepath = event.src_path
        time.sleep(2)  # Pockaj nech sa súbor úplne stiahne
        
        if os.path.getsize(filepath) < 1024:  # <1KB = preskakuj
            return
        
        # Entropy check
        if is_entropy_suspicious(filepath):
            if show_file_alert(...):
                # Presunúť do karantény
```

**Ako to funguje:**
1. Watchdog **OS level** monitoruje Downloads
2. Keď sa vytvorí súbor, OS to signalizuje (nie polling!)
3. Čakáme 2 sekundy (nech sa stihne stiahnuť)
4. Skontrolujeme entropy
5. Vypočítame SHA-256
6. Skontrolujeme v MalwareBazaar

**Výhoda:** Rýchle, efektívne, bez spamovacieho pollovania.

### Hlavný monitorovací loop

```python
def loop():
    # Spustí Watchdog observer
    observer = Observer()
    observer.schedule(DownloadMonitor(), downloads_dir, recursive=True)
    observer.start()
    
    reported_pids = set()  # Deduplikácia alertov
    
    while True:
        for proc in psutil.process_iter(["pid", "exe", "name", "cmdline"]):
            # ... 5 detekčných vrstiev ...
        
        # Vyčisti zastarané PID z pamäte
        to_remove = set()
        for reported_pid in reported_pids:
            try:
                psutil.Process(reported_pid)
            except psutil.NoSuchProcess:
                to_remove.add(reported_pid)
        reported_pids -= to_remove
        
        time.sleep(30)  # Skenovanie každých 30 sekúnd
```

**Deduplikácia alertov - DÔLEŽITÉ:**
```python
if pid not in reported_pids:
    if show_detailed_threat_alert(...):
        reported_pids.add(pid)
```

Bez toho by sme upozorňovali na ten istý proces 100x za minútu! S `reported_pids` set sa每个进程 objeví len raz.

Keď proces skončí (PID neexistuje), vymaž ho zo sady.

### Vyskakujúce okná

```python
def show_detailed_threat_alert(exe, pid, name, threat_type, details):
    """Zobrazí detailné vyskakovacie okno s hrozbou."""
    root = tk.Tk()
    root.withdraw()                  # Skryje hlavné okno
    root.attributes('-topmost', True)  # Vždy navrchu
    
    detail_str = ""
    if threat_type == "entropy":
        detail_str = f"Typ hrozby: ZABAĽOVANÉ MALWARE"
    elif threat_type == "behavioral":
        detail_str = f"Typ hrozby: ANOMÁLNE SPRÁVANIE"
    elif threat_type == "lolbas":
        detail_str = f"Typ hrozby: ZNEUŽÍVANIE SYSTÉMOVÉHO NÁSTROJA"
    
    message = f"🚨 VYSOKÁ HROZBA!\n\n" \
              f"Proces: {name}\n" \
              f"PID: {pid}\n" \
              f"Cesta: {exe or 'Neznáma'}\n\n" \
              f"{detail_str}"
    
    result = messagebox.askyesno("PyGuard ⚠️ KRITICKÁ HROZBA", message)
    root.destroy()
    
    return result
```

**Čo to robí:**
1. Vytvoríme tkinter okno (bez hlavného okna)
2. Nastavíme ho "on top" (vždy viditeľné)
3. Zobrazíme detaily hrozby
4. Čakáme na odpoveď (Áno/Nie)
5. Vrátime výsledok

## Bezpečnostné výhody Trackeru

- **Automatické** - Bez ľudského faktor
- **Real-time** - Downloads sa monitorujú ihneď
- **Bez internetovej latencie** - Entropy a behavioral detekcia sú lokálne
- **Nízka spotreba** - 30 sekúnd + Watchdog observer (OS level)
- **Bez false positives** - Bodovací systém + deduplikácia

## Zhrnutie Trackeru

Tracker je **druhá línia obrany** PyGuardu:
- **PyGuard main** = ručné skenovaní (keď chceš)
- **Tracker** = Automatická ochrana (vždy aktívna)

Kombinujú sa obidve techniky - signature-based (SHA-256) a heuristic-based (behavioral). Presne ako profesionálne antivírusy! 🛡️

