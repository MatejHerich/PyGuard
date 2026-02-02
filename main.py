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

# Karanténa: priečinok pre nebezpečné súbory (možno prepísať v .env ako QUARANTINE_PATH)
_QUARANTINE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PyGuard_Quarantine")

def get_welcome_screen():
    """Vráti farebný uvítací banner."""
    logo_lines = [
        r"  _____ __     _______ _    _         _____  _____  ",
        r" |  __ \\ \   / / ____| |  | |  /\   |  __ \|  __ \ ",
        r" | |__) |\ \_/ / |  __| |  | | /  \  | |__) | |  | |",
        r" |  ___/  \   /| | |_ | |  | |/ /\ \ |  _  /| |  | |",
        r" | |       | | | |__| | |__| / ____ \| | \ \| |__| |",
        r" |_|       |_|  \_____|\____/_/    \_\_|  \_\_____/ ",
    ]
    lines = []
    for line in logo_lines:
        lines.append(click.style(line, fg='cyan'))
    lines.append("")
    lines.append(click.style(" >>> PYGUARD: Python Security & Antivirus Mentor", fg='green'))
    lines.append(click.style(" >>> Status: Active | Version: 1.0.0", fg='yellow'))
    lines.append(click.style(" ---------------------------------------------------", fg='bright_black'))
    return "\n".join(lines)

WELCOME_SCREEN = None  # bude nastavené pri štarte

def calculate_sha256(filepath):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        click.echo(f"❌ Chyba pri výpočte SHA-256: {e}")
        return None


def check_hash_malwarebazaar(sha256_hash):
    """
    Skontroluje SHA-256 hash v databáze MalwareBazaar (abuse.ch).
    Vyžaduje voľný API kľúč v premennej ABUSE_CH_API_KEY.
    Registrácia: https://auth.abuse.ch/
    """
    api_key = os.environ.get("ABUSE_CH_API_KEY")
    if not api_key:
        click.echo("⚠️  Pre kontrolu proti MalwareBazaar nastav premennú ABUSE_CH_API_KEY")
        click.echo("   (voľný kľúč: https://auth.abuse.ch/)")
        return None

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
        click.echo(f"❌ Chyba API MalwareBazaar: {e}")
        return None


def get_quarantine_dir():
    """Vráti cestu ku karanténe a priečinok vytvorí, ak neexistuje."""
    path = os.environ.get("QUARANTINE_PATH", _QUARANTINE_DEFAULT)
    os.makedirs(path, exist_ok=True)
    return path


def kill_processes_using_file(filepath):
    """Ukončí všetky procesy, ktoré bežia z daného súboru (exe)."""
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


def move_to_quarantine(filepath):
    """
    Ukončí procesy súboru, presunie súbor do karantény s jedinečným menom
    a nastaví ho ako len na čítanie (obmedzenie spustenia).
    """
    if not os.path.isfile(filepath):
        click.echo(f"❌ Súbor neexistuje: {filepath}")
        return False

    abs_path = os.path.abspath(filepath)
    qdir = get_quarantine_dir()

    click.echo("🔄 Ukončujem procesy súvisiace so súborom...")
    n = kill_processes_using_file(abs_path)
    if n:
        time.sleep(0.5)  # chvíľa na ukončenie

    base = os.path.basename(abs_path)
    name, ext = os.path.splitext(base)
    # Jedinečné meno: pôvodné_meno_časť_času.rozšírenie.quarantined
    unique = f"{name}_{int(time.time())}{ext}.quarantined"
    dest = os.path.join(qdir, unique)

    try:
        shutil.move(abs_path, dest)
        try:
            os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass  # na niektorých systémoch chmod môže zlyhať, súbor je už v karanténe
        click.echo(f"✅ Súbor presunutý do karantény: {dest}")
        return True
    except Exception as e:
        click.echo(f"❌ Chyba pri presune do karantény: {e}")
        return False


@shell.shell(prompt='PyGuard > ', intro='')
def cli():
    # Táto funkcia musí byť prázdna, slúži len ako vstup do shellu
    pass

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def scanf(filepath):
    """Scan a file for potential threats (SHA-256 vs. MalwareBazaar)."""
    click.echo(f"🔍 Skenujem súbor: {filepath}")

    with click.progressbar(length=100, label='Výpočet SHA-256', show_percent=False) as bar:
        sha256 = calculate_sha256(filepath)
        bar.update(100)
    
    if sha256 is None:
        return

    click.echo(f"📋 SHA-256: {sha256}")
    click.echo("🔄 Kontrolujem v databáze MalwareBazaar...")
    
    result = check_hash_malwarebazaar(sha256)
    if result is None:
        return  # chýba API kľúč alebo chyba sieťe
    if result:
        click.echo("🚨 VÝSTRAHA: Hash bol nájdený v databáze malvérov (MalwareBazaar)!")
        for entry in result[:3]:  # max prvé 3 záznamy
            tag = entry.get("tags", ["?"])[0] if entry.get("tags") else "?"
            click.echo(f"   → Tag: {tag}")
    else:
        click.echo("✅ Hash nebol nájdený v databáze MalwareBazaar (súbor neznamená známy malvér).")


@cli.command()
@click.argument('dirpath', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--recursive', '-r', is_flag=True, default=True, help='Skenovať aj podpriečinky (predvolené: zapnuté).')
@click.option('--no-recursive', is_flag=True, help='Skenovať len súbory v danom priečinku (nie podpriečinky).')
def scand(dirpath, recursive, no_recursive):
    """Skenuje priečinok: SHA-256 vs. MalwareBazaar pre každý súbor."""
    if no_recursive:
        recursive = False

    click.echo(f"🔍 Skenujem priečinok: {dirpath}" + (" (rekurzívne)" if recursive else " (len tento priečinok)"))

    if not os.environ.get("ABUSE_CH_API_KEY"):
        click.echo("⚠️  Pre kontrolu proti MalwareBazaar nastav premennú ABUSE_CH_API_KEY")
        return

    files_to_scan = []
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

    if not files_to_scan:
        click.echo("📂 V priečinku nie sú žiadne súbory na skenovanie.")
        return

    click.echo(f"   Nájdených súborov: {len(files_to_scan)}")
    threats = []

    with click.progressbar(files_to_scan, label='Skenovanie', show_pos=True, show_percent=True) as bar:
        for path in bar:
            sha256 = calculate_sha256(path)
            if sha256 is None:
                continue
            result = check_hash_malwarebazaar(sha256)
            if result is None:
                continue
            if result:
                tag = result[0].get("tags", ["?"])[0] if result[0].get("tags") else "?"
                click.echo(f"\n🚨 VÝSTRAHA: {path}")
                click.echo(f"   SHA-256: {sha256}  → Tag: {tag}")
                threats.append(path)

    click.echo("")
    click.echo(f"📊 Skenované: {len(files_to_scan)} súborov  |  Nájdené hrozby: {len(threats)}")
    if threats:
        click.echo("   Odporúčanie: na karanténu použite príkaz quarantine <cesta> pre každý súbor.")


@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def quarantine(filepath):
    """Ukončí procesy súboru a bezpečne ho presunie do karantény (žiadne spustenie)."""
    click.echo(f"🔒 Presúvam do karantény: {filepath}")
    move_to_quarantine(filepath)


@cli.command('quarantine-list')
def quarantine_list():
    """Zobrazí súbory v karanténe."""
    qdir = get_quarantine_dir()
    try:
        entries = [e for e in os.listdir(qdir) if os.path.isfile(os.path.join(qdir, e))]
    except OSError as e:
        click.echo(f"❌ Chyba pri čítaní karantény: {e}")
        return
    if not entries:
        click.echo("📂 Karanténa je prázdna.")
        return
    click.echo(f"📂 Karanténa ({qdir}):")
    for e in sorted(entries):
        click.echo(f"   • {e}")


@cli.command('quarantine-clear')
@click.confirmation_option(prompt='Naozaj vymazať všetky súbory v karanténe?')
def quarantine_clear():
    """Trvalo vymaže všetky súbory v karanténe."""
    qdir = get_quarantine_dir()
    try:
        entries = [os.path.join(qdir, e) for e in os.listdir(qdir) if os.path.isfile(os.path.join(qdir, e))]
    except OSError as e:
        click.echo(f"❌ Chyba pri čítaní karantény: {e}")
        return
    if not entries:
        click.echo("📂 Karanténa je už prázdna.")
        return
    for path in entries:
        try:
            os.chmod(path, stat.S_IWUSR)
            os.remove(path)
            click.echo(f"   Vymazané: {os.path.basename(path)}")
        except OSError as e:
            click.echo(f"   ❌ {os.path.basename(path)}: {e}")
    click.echo("✅ Karanténa vymazaná.")

if __name__ == '__main__':
    click.echo(get_welcome_screen())
    cli()