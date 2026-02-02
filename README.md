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
