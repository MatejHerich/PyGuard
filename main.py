import click
import click_shell as shell
import os
import hashlib

WELCOME_SCREEN = r"""
  _____ __     _______ _    _         _____  _____  
 |  __ \\ \   / / ____| |  | |  /\   |  __ \|  __ \ 
 | |__) |\ \_/ / |  __| |  | | /  \  | |__) | |  | |
 |  ___/  \   /| | |_ | |  | |/ /\ \ |  _  /| |  | |
 | |       | | | |__| | |__| / ____ \| | \ \| |__| |
 |_|       |_|  \_____|\____/_/    \_\_|  \_\_____/ 

 >>> PYGUARD: Python Security & Antivirus Mentor
 >>> Status: Active | Version: 1.0.0
 ---------------------------------------------------
"""

@shell.shell(prompt='PyGuard > ', intro=WELCOME_SCREEN)
def cli():
    # Táto funkcia musí byť prázdna, slúži len ako vstup do shellu
    pass

@cli.command()
@click.argument('filepath', type=click.Path(exists=True))
def scanf(filepath):
    """Scan a file for potential threats."""
    click.echo(f"🔍 Skenujem súbor: {filepath}")
    # Sem teraz doplníme tú logiku hashlib, ktorú sme riešili minule

if __name__ == '__main__':
    cli()