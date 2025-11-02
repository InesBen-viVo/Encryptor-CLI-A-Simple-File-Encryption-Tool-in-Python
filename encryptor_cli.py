#!/usr/bin/env python3
# encryptor_cli.py
"""
Simple CLI encrypt/decrypt tool using password-derived keys (PBKDF2) + Fernet.
"""

import os
import base64
from getpass import getpass
from time import sleep

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from rich.console import Console
from rich.panel import Panel
import pyfiglet

console = Console()

# Constants
SALT_SIZE = 16            # bytes
KDF_ITERATIONS = 390000   # recommended: high enough to be slow for attackers
BACKEND = default_backend()


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password+salt using PBKDF2-HMAC-SHA256, return urlsafe base64 key for Fernet."""
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=BACKEND
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


def encrypt_message(plaintext: str, password: str) -> str:
    """Encrypt plaintext with a password. Return a single base64 string containing salt + ciphertext."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))  # token is bytes
    blob = salt + token  # prepend salt
    return base64.urlsafe_b64encode(blob).decode("utf-8")


def decrypt_message(blob_b64: str, password: str) -> str:
    """Decrypt the base64(salt + token) with the password. Return plaintext or raise InvalidToken."""
    try:
        blob = base64.urlsafe_b64decode(blob_b64)
    except Exception as e:
        raise ValueError("Input is not valid base64 or is corrupted.") from e

    if len(blob) <= SALT_SIZE:
        raise ValueError("Input is too short or missing ciphertext.")

    salt = blob[:SALT_SIZE]
    token = blob[SALT_SIZE:]
    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        plaintext_bytes = f.decrypt(token)
        return plaintext_bytes.decode("utf-8")
    except InvalidToken as e:
        raise InvalidToken("Decryption failed — wrong password or corrupted data.") from e


def banner():
    fig = pyfiglet.figlet_format("ENCRYPTOR", font="slant")
    console.print(f"[bold cyan]{fig}[/bold cyan]")
    console.print(Panel("[bold]Secure encrypt/decrypt CLI[/bold]\n[dim]PBKDF2 + Fernet (cryptography)[/dim]", expand=False))


def main():
    banner()
    try:
        while True:
            console.print("\n[bold]Choose:[/bold] (e) Encrypt  •  (d) Decrypt  •  (q) Quit")
            choice = console.input("[bold magenta]> [/bold magenta]").strip().lower()
            if choice in ("q", "quit", "exit"):
                console.print("\n[dim]Bye — keep your secrets safe.[/dim]")
                break

            if choice == "e":
                msg = console.input("Enter message to encrypt: ")
                password = getpass("Enter password (will not echo): ")
                password_confirm = getpass("Confirm password: ")
                if password != password_confirm:
                    console.print("[red]Passwords do not match. Try again.[/red]")
                    continue

                console.print("[cyan]Encrypting...[/cyan]")
                sleep(0.4)
                blob = encrypt_message(msg, password)
                console.print(Panel(f"[green]Encrypted output (copy & save):[/green]\n\n{blob}", title="ENCRYPTED"))
                console.print("[dim]Store this whole string safely. You need it + your password to decrypt.[/dim]")

            elif choice == "d":
                blob = console.input("Paste base64 package (salt+ciphertext): ")
                password = getpass("Enter password used to encrypt: ")
                console.print("[cyan]Decrypting...[/cyan]")
                sleep(0.4)
                try:
                    plain = decrypt_message(blob.strip(), password)
                    console.print(Panel(f"[bold]Decrypted message:[/bold]\n\n{plain}", title="PLAINTEXT"))
                except Exception as e:
                    console.print(f"[red]Error:[/red] {e}")

            else:
                console.print("[yellow]Unknown option. Use 'e' or 'd' or 'q'.[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted. Bye.[/dim]")


if __name__ == "__main__":
    main()
