# PyGuard – Python Security & Antivirus Mentor

PyGuard je konzolová aplikácia v Pythone, ktorá umožňuje skenovať súbory a priečinky podľa SHA-256 hashu a porovnávať ich s verejnou databázou malvérov **MalwareBazaar** (abuse.ch). Podozrivé súbory môžeš presunúť do karantény, ukončiť ich procesy a neskôr karanténu vymazať.

---

## Obsah

1. [Inštalácia a spustenie](#inštalácia-a-spustenie)
2. [Konfigurácia](#konfigurácia)
3. [Prehľad príkazov](#prehľad-príkazov)
4. [Popis kódu](#popis-kódu)
5. [Bezpečnostné poznámky](#bezpečnostné-poznámky)

---

## Inštalácia a spustenie

### Požiadavky

- Python 3.x
- Závislosti z `requirements.txt`

### Inštalácia závislostí

Ak `pip` nie je v PATH, použite:

```bash
python -m pip install -r requirements.txt
```

### Spustenie

```bash
python main.py
```

Zobrazí sa uvítacia obrazovka a shell s výzvou `PyGuard > `. Odtiaľ voláš príkazy.

---

## Konfigurácia

- **API kľúč MalwareBazaar:** Ulož ho do súboru `.env` v koreni projektu (súbor sa necommitne do gitu). Voľný kľúč získáš na [https://auth.abuse.ch/](https://auth.abuse.ch/).
- **Karanténa:** Predvolene je priečinok `PyGuard_Quarantine` vedľa `main.py`. Cestu môžeš prepísať v `.env` premennou `QUARANTINE_PATH`.

Príklad `.env`:

```
ABUSE_CH_API_KEY=tvoj_api_kluc
QUARANTINE_PATH=C:\MojaKarantena
```

---

## Prehľad príkazov

| Príkaz | Popis |
|--------|--------|
| `scanf <cesta_k_súboru>` | Skenuje jeden súbor (SHA-256 vs. MalwareBazaar). |
| `scand <cesta_k_priečinku>` | Skenuje celý priečinok (predvolene rekurzívne). Možnosti: `--no-recursive` = len súbory v danom priečinku. |
| `quarantine <cesta_k_súboru>` | Ukončí procesy súboru a presunie ho do karantény. |
| `quarantine-list` | Zobrazí zoznam súborov v karanténe. |
| `quarantine-clear` | Trvalo vymaže všetky súbory v karanténe (s potvrdením). |

---

## Popis kódu

Nasleduje podrobný popis štruktúry programu a jednotlivých častí kódu.

---

### 1. Importy a úvodná konfigurácia

Program používa knižnice na prácu s príkazovým riadkom (`click`, `click_shell`), súbormi a hashovaním (`hashlib`, `os`, `shutil`, `stat`), sieťovými požiadavkami (`requests`), procesmi (`psutil`) a načítaním premenných z `.env` (`python-dotenv`).

```python
import click
import click_shell as shell
import os
import hashlib
import shutil
import stat
import time
import requests
import psutil
from dotenv import load_dotenv

load_dotenv()  # načíta ABUSE_CH_API_KEY z .env (súbor nie je v gite)
```

`load_dotenv()` načíta premenné z `.env` do `os.environ`, takže `ABUSE_CH_API_KEY` a voliteľne `QUARANTINE_PATH` sú k dispozícii v celom programe.

Karanténa má predvolenú cestu: priečinok `PyGuard_Quarantine` v tom istom adresári, kde leží `main.py`:

```python
_QUARANTINE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PyGuard_Quarantine")
```

---

### 2. Výpočet SHA-256 hashu súboru

Funkcia `calculate_sha256(filepath)` prečíta súbor po blokoch (4096 bajtov), aktualizuje SHA-256 hash a vráti jeho hexadecimálny reťazec. Pri chybe (napr. súbor neexistuje alebo nemáš oprávnenia) vráti `None` a vypíše chybovú hlášku.

```python
def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        click.echo(f"❌ Chyba pri výpočte SHA-256: {e}")
        return None
```

Čítanie po blokoch je dôležité pre veľké súbory, aby sa nezaťažovala pamäť.

---

### 3. Kontrola hashu v MalwareBazaar

Funkcia `check_hash_malwarebazaar(sha256_hash)` odošle SHA-256 hash na API MalwareBazaar (abuse.ch). Ak nie je nastavený `ABUSE_CH_API_KEY`, vypíše upozornenie a vráti `None`. Ak API vráti záznamy o malvéroch, vráti zoznam záznamov; ak hash v databáze nie je, vráti prázdny zoznam `[]`.

```python
def check_hash_malwarebazaar(sha256_hash):
    api_key = os.environ.get("ABUSE_CH_API_KEY")
    if not api_key:
        click.echo("⚠️  Pre kontrolu proti MalwareBazaar nastav premennú ABUSE_CH_API_KEY")
        return None

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": api_key}
    data = {"query": "get_info", "hash": sha256_hash}

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=15)
        resp.raise_for_status()
        j = resp.json()
        if j.get("query_status") == "ok" and j.get("data"):
            return j["data"]
        return []
    except requests.RequestException as e:
        click.echo(f"❌ Chyba API MalwareBazaar: {e}")
        return None
```

Význam návratových hodnôt:

- `None` = chýba kľúč alebo sieťová/API chyba
- `[]` = hash nie je v databáze (súbor nie je známy malvér)
- neprázdny zoznam = hash bol nájdený v databáze (súbor je považovaný za malvér)

---

### 4. Karanténa – získanie priečinka

Funkcia `get_quarantine_dir()` vráti cestu ku karanténnemu priečinku. Ak je v `.env` nastavená `QUARANTINE_PATH`, použije sa tá; inak predvolená `PyGuard_Quarantine`. Priečinok sa vytvorí, ak ešte neexistuje.

```python
def get_quarantine_dir():
    path = os.environ.get("QUARANTINE_PATH", _QUARANTINE_DEFAULT)
    os.makedirs(path, exist_ok=True)
    return path
```

---

### 5. Ukončenie procesov súboru

Funkcia `kill_processes_using_file(filepath)` prechádza všetky bežiace procesy (vďaka `psutil.process_iter()`), porovná cestu k ich spustiteľnému súboru (`proc.info.get("exe")`) s absolútnou cestou k nášmu súboru. Ak sa zhodujú, proces ukončí (`proc.kill()`). Na niektoré procesy môže byť potrebné spustiť PyGuard ako správca.

```python
def kill_processes_using_file(filepath):
    abs_path = os.path.abspath(filepath)
    killed = 0
    try:
        for proc in psutil.process_iter(["pid", "exe", "name"]):
            try:
                exe = proc.info.get("exe")
                if exe and os.path.normpath(exe) == os.path.normpath(abs_path):
                    proc.kill()
                    killed += 1
                    click.echo(f"   Ukončený proces PID {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        click.echo(f"⚠️  Chyba pri ukončovaní procesov: {e}")
    return killed
```

---

### 6. Presun súboru do karantény

Funkcia `move_to_quarantine(filepath)`:

1. Skontroluje, či je `filepath` skutočne súbor.
2. Zavolá `kill_processes_using_file()` a krátko počkať (`time.sleep(0.5)`), aby sa procesy stihli ukončiť.
3. Vytvorí jedinečné meno súboru v karanténe: `pôvodné_meno_časť_času.rozšírenie.quarantined` (čas v sekundách zabráni prepisovaniu).
4. Presunie súbor pomocou `shutil.move()`.
5. Nastaví súbor na len na čítanie (`os.chmod(..., S_IRUSR | S_IRGRP | S_IROTH)`), čo na niektorých systémoch pomáha obmedziť spustenie. Na Windows môže `chmod` zlyhať, preto je v `try/except` a chyba sa ignoruje.

```python
unique = f"{name}_{int(time.time())}{ext}.quarantined"
dest = os.path.join(qdir, unique)
shutil.move(abs_path, dest)
try:
    os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
except OSError:
    pass
```

---

### 7. Shell a príkaz `scanf`

Aplikácia používa **click_shell**: po spustení `python main.py` vstúpiš do interaktívneho shellu s výzvou `PyGuard > `. Jednotlivé príkazy sú registrované cez `@cli.command()`.

Príkaz `scanf`:

- Prijme jeden argument: cestu k súboru (`click.Path(exists=True)`).
- Vypočíta SHA-256 cez `calculate_sha256()`.
- Odošle hash do MalwareBazaar cez `check_hash_malwarebazaar()`.
- Podľa odpovede vypíše, či bol súbor nájdený v databáze malvérov, prípadne tagy (napr. trojan, ransomware).

```python
@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def scanf(filepath):
    sha256 = calculate_sha256(filepath)
    if sha256 is None:
        return
    result = check_hash_malwarebazaar(sha256)
    if result:
        click.echo("🚨 VÝSTRAHA: Hash bol nájdený v databáze malvérov (MalwareBazaar)!")
        # ... výpis tagov
    else:
        click.echo("✅ Hash nebol nájdený v databáze MalwareBazaar ...")
```

---

### 8. Príkaz `scand` (skenovanie priečinka)

Príkaz `scand` prijíma cestu k **priečinku** (`file_okay=False`, `dir_okay=True`). Voliteľné prepínače:

- `--recursive` / `-r` (predvolene zapnuté): skenuje aj všetky podpriečinky.
- `--no-recursive`: skenuje len súbory priamo v danom priečinku.

Postup:

1. Zozbiera všetky súbory v priečinku (prípadne rekurzívne cez `os.walk()`). Symbolické odkazy sa preskakujú.
2. Pre každý súbor vypočíta SHA-256 a odošle ho do MalwareBazaar.
3. Pri nájdení hrozby vypíše cestu, SHA-256 a tag.
4. Na konci vypíše zhrnutie: počet skenovaných súborov a počet nájdených hrozieb.

```python
if recursive:
    for root, _dirs, files in os.walk(dirpath):
        for name in files:
            path = os.path.join(root, name)
            if os.path.isfile(path) and not os.path.islink(path):
                files_to_scan.append(path)
else:
    for name in os.listdir(dirpath):
        path = os.path.join(dirpath, name)
        if os.path.isfile(path) and not os.path.islink(path):
            files_to_scan.append(path)
```

---

### 9. Príkaz `quarantine`

Príkaz `quarantine <filepath>` len zavolá `move_to_quarantine(filepath)`, ktorá ukončí procesy a presunie súbor do karantény, ako je popísané vyššie.

---

### 10. Príkaz `quarantine-list`

Prečíta obsah karanténneho priečinka (`get_quarantine_dir()`), zobrazí len položky, ktoré sú súbory (nie podpriečinky), a vypíše ich zoradené podľa mena.

---

### 11. Príkaz `quarantine-clear`

S potvrdením (`@click.confirmation_option`) vymaže všetky súbory v karanténe: najprv zmení oprávnenia na zapisovateľné (`os.chmod(path, stat.S_IWUSR)`), potom súbor vymaže (`os.remove(path)`). Bez zmeny oprávnení by sa súbory nastavené na len na čítanie nedali vymazať.

```python
for path in entries:
    try:
        os.chmod(path, stat.S_IWUSR)
        os.remove(path)
        click.echo(f"   Vymazané: {os.path.basename(path)}")
    except OSError as e:
        click.echo(f"   ❌ {os.path.basename(path)}: {e}")
```

---

## Bezpečnostné poznámky

- Súbor **`.env`** obsahuje API kľúč a nemal by sa nikdy commitovať do gitu (je v `.gitignore`). Nikdy ho neposielaj verejne.
- Karanténa **nešifruje** súbory; sú len presunuté a označené ako nebezpečné. Ak potrebuješ trvalé zničenie, použite `quarantine-clear` až keď si istý.
- Na ukončenie niektorých systémových alebo chránených procesov môže byť potrebné spustiť PyGuard **ako správca** (Run as administrator).

---

## Zhrnutie toku programu

1. **Spustenie** → `load_dotenv()` načíta `.env` → zobrazí sa shell.
2. **scanf / scand** → výpočet SHA-256 → odoslanie na MalwareBazaar → výpis výsledku.
3. **quarantine** → ukončenie procesov súboru → presun do karantény s jedinečným menom → nastavenie len na čítanie.
4. **quarantine-list** → výpis súborov v karanténe.
5. **quarantine-clear** → potvrdenie → zmena oprávnení a vymazanie všetkých súborov v karanténe.

Tým máš kompletný prehľad o tom, ako PyGuard funguje a ako je kód štruktúrovaný.
