"""Fest versionierte, ausschließlich lokal gespeicherte Wortlisten."""

from __future__ import annotations

import gzip
import hashlib
import os
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


SECLISTS_REV = "49c9fcd20e0945f24ec854872f265eb3d13c3741"
KALI_REV = "7d461801f64424c8a5004238f07c2ece584e647b"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    sha256: str
    compressed: bool = False
    content_sha256: str | None = None


SOURCES = (
    Source(
        "seclists-10k.txt",
        f"https://raw.githubusercontent.com/danielmiessler/SecLists/{SECLISTS_REV}/Passwords/Common-Credentials/10k-most-common.txt",
        "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce",
    ),
    Source(
        "seclists-100k.txt",
        f"https://raw.githubusercontent.com/danielmiessler/SecLists/{SECLISTS_REV}/Passwords/Common-Credentials/Pwdb_top-100000.txt",
        "07f876a616f08fb2cc5c3e0ce04e4a6d1123380580472b0997baebc4e8226977",
    ),
    Source(
        "rockyou.txt",
        f"https://gitlab.com/kalilinux/packages/wordlists/-/raw/{KALI_REV}/rockyou.txt.gz",
        "ded2d962815e1256df8f3a0d25173c4b21b6eee636117c36999246725a6d8f9f",
        compressed=True,
        content_sha256="16035fea7742cb0561c513de1d946eda5716d7de294e6c732449740096686173",
    ),
)


def available_wordlists(cache: Path, download: bool) -> tuple[list[Path], list[str]]:
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    found: list[Path] = []
    errors: list[str] = []
    for source in SOURCES:
        target = cache / source.name
        expected = source.content_sha256 or source.sha256
        if target.is_file() and _sha256(target) == expected:
            found.append(target)
            continue
        if not download:
            if target.exists():
                errors.append(f"{source.name}: lokale Prüfsumme stimmt nicht")
            continue
        try:
            _fetch(source, target)
            found.append(target)
        except (OSError, ValueError, EOFError) as exc:
            errors.append(f"{source.name}: {exc}")
    return found, errors


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _fetch(source: Source, target: Path) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=".download-", dir=target.parent)
    temp = Path(temp_name)
    archive = target.parent / (temp.name + ".gz")
    try:
        os.close(fd)
        digest = hashlib.sha256()
        request = urllib.request.Request(source.url, headers={"User-Agent": "DocDecrypt/0.1"})
        with urllib.request.urlopen(request, timeout=45) as remote, archive.open("wb") as output:
            count = 0
            while block := remote.read(1024 * 1024):
                count += len(block)
                if count > 200 * 1024 * 1024:
                    raise ValueError("Download überschreitet 200 MiB")
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != source.sha256:
            raise ValueError("Prüfsumme stimmt nicht")
        with (gzip.open(archive, "rb") if source.compressed else archive.open("rb")) as data, temp.open("wb") as output:
            count = 0
            while block := data.read(1024 * 1024):
                count += len(block)
                if count > 500 * 1024 * 1024:
                    raise ValueError("Entpackte Liste überschreitet 500 MiB")
                output.write(block)
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
