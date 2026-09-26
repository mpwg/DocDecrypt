"""Erkennung, Prüfdatenextraktion und verifizierte Entschlüsselung."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import msoffcrypto
from msoffcrypto.exceptions import InvalidKeyError


VENDORED_OFFICE2JOHN = Path(__file__).parent / "_vendor" / "office2john.py"
HASH_PATTERN = re.compile(r"\$(?:oldoffice\$[0-9]+|office\$\*20(?:07|10|13))\*")
MODE_BY_TYPE = {"0": 9700, "1": 9700, "3": 9800, "4": 9800}
MODE_BY_YEAR = {"2007": 9400, "2010": 9500, "2013": 9600}


class UnsupportedDocumentError(Exception):
    """Das Format kann mit den verfügbaren Werkzeugen nicht bearbeitet werden."""


def is_encrypted(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return bool(msoffcrypto.OfficeFile(stream).is_encrypted())
    except Exception as exc:
        raise UnsupportedDocumentError(f"Datei nicht lesbar: {exc}") from exc


def extract_hash(path: Path) -> tuple[str, int]:
    result = subprocess.run(
        [sys.executable, str(VENDORED_OFFICE2JOHN), str(path)],
        capture_output=True, text=True, errors="replace", check=False,
    )
    match = HASH_PATTERN.search(result.stdout)
    if not match:
        reason = result.stderr.strip().splitlines()
        raise UnsupportedDocumentError(reason[-1] if reason else "Keine unterstützten Prüfdaten gefunden")
    hash_value = result.stdout[match.start():].split(":::", 1)[0].strip().splitlines()[0]
    if hash_value.startswith("$oldoffice$"):
        kind = hash_value.split("$", 2)[2].split("*", 1)[0]
        mode = MODE_BY_TYPE.get(kind)
    else:
        year = hash_value.split("*", 2)[1]
        mode = MODE_BY_YEAR.get(year)
    if mode is None:
        raise UnsupportedDocumentError("Hash-Verfahren wird von hashcat nicht unterstützt")
    return hash_value, mode


def decrypt_to(path: Path, destination: Path, password: str) -> bool:
    """Entschlüsselt atomar; falsche Passwörter erzeugen keine Ausgabedatei."""
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".docdecrypt-", dir=destination.parent)
    temp = Path(temp_name)
    try:
        with path.open("rb") as encrypted, os.fdopen(fd, "wb") as decrypted:
            office = msoffcrypto.OfficeFile(encrypted)
            try:
                office.load_key(password=password)
                office.decrypt(decrypted)
            except (InvalidKeyError, ValueError):
                return False
        if is_encrypted(temp):
            raise UnsupportedDocumentError("Entschlüsseltes Ergebnis ist weiterhin verschlüsselt")
        os.replace(temp, destination)
        return True
    finally:
        temp.unlink(missing_ok=True)


def copy_plain(path: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".docdecrypt-", dir=destination.parent)
    temp = Path(temp_name)
    try:
        with path.open("rb") as source, os.fdopen(fd, "wb") as target:
            shutil.copyfileobj(source, target)
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)
