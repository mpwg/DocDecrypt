"""Ablauf und lokaler Wiederaufnahmestand."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from .attacks import Stage, context_wordlist, execute_stage, stages
from .office import UnsupportedDocumentError, copy_plain, decrypt_to, extract_hash, is_encrypted
from .sources import available_wordlists


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"completed": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("completed"), list):
            return data
    except (OSError, ValueError):
        pass
    return {"completed": []}


def _save_state(path: Path, state: dict) -> None:
    _write_private(path, json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def _identity(path: Path) -> str:
    digest = hashlib.sha256(str(path.resolve()).encode("utf-8"))
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()[:24]


def _stage_key(stage: Stage) -> str:
    value = (stage.name, stage.attack, stage.inputs, stage.mode, stage.collision)
    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()[:16]


def _known_passwords(state_dir: Path) -> list[str]:
    passwords: list[str] = []
    for path in state_dir.glob("*.json"):
        value = _load_state(path).get("password")
        if isinstance(value, str) and value not in passwords:
            passwords.append(value)
    return passwords


def _print_password(path: Path, password: str) -> None:
    # JSON maskiert Zeilenumbrüche und Steuerzeichen, ohne das Passwort zu verändern.
    print(f"Passwort für {path.name}: {json.dumps(password, ensure_ascii=False)}")


def _process_file(
    path: Path, output_dir: Path, private_dir: Path, own_lists: list[Path],
    downloaded: list[Path], seconds_per_file: float,
) -> bool:
    file_id = _identity(path)
    state_file = private_dir / "state" / f"{file_id}.json"
    state = _load_state(state_file)
    destination = output_dir / path.name
    state.update({"source": str(path), "output": str(destination)})
    if not is_encrypted(path):
        copy_plain(path, destination)
        state["status"] = "unverschlüsselt"
        _save_state(state_file, state)
        print(f"{path.name}: bereits unverschlüsselt")
        return True
    if state.get("status") == "entschlüsselt" and destination.is_file():
        print(f"{path.name}: bereits entschlüsselt")
        if isinstance(state.get("password"), str):
            _print_password(path, state["password"])
        return True
    deadline = time.monotonic() + seconds_per_file
    for password in _known_passwords(private_dir / "state"):
        if decrypt_to(path, destination, password):
            state.update({"status": "entschlüsselt", "password": password})
            _save_state(state_file, state)
            print(f"{path.name}: mit bekanntem Passwort entschlüsselt")
            _print_password(path, password)
            return True
    hash_value, mode = extract_hash(path)
    hash_file = private_dir / f"{file_id}.hash"
    _write_private(hash_file, hash_value + "\n")
    context = context_wordlist(path, private_dir / f"{file_id}.wordlist")
    attacks = stages(own_lists, context, downloaded, mode, hash_value)
    completed = set(state.get("completed", []))
    exhausted = True
    for stage in attacks:
        key = _stage_key(stage)
        if key in completed:
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exhausted = False
            break
        if stage.collision:
            collision_key = state.get("collision_key")
            if not isinstance(collision_key, str):
                continue
            attack_hash = private_dir / f"{file_id}.collision.hash"
            _write_private(attack_hash, f"{hash_value}:{collision_key}\n")
        else:
            attack_hash = hash_file
        print(f"{path.name}: {stage.name}", flush=True)
        found, finished, error = execute_stage(
            stage, key, attack_hash, mode, private_dir, file_id, remaining,
        )
        if error:
            state.update({"status": "fehler", "error": error})
            _save_state(state_file, state)
            print(f"  Fehler: {error}")
            return False
        if found is not None:
            if stage.mode == 9710:
                state["collision_key"] = found
            elif decrypt_to(path, destination, found):
                state.update({"status": "entschlüsselt", "password": found})
                _save_state(state_file, state)
                print(f"{path.name}: entschlüsselt")
                _print_password(path, found)
                return True
            else:
                print("  Kandidat konnte das Dokument nicht entschlüsseln")
        if finished:
            completed.add(key)
            state["completed"] = sorted(completed)
            state["status"] = "suche"
            _save_state(state_file, state)
        else:
            exhausted = False
            break
    state["status"] = "nicht gefunden" if exhausted else "pausiert"
    _save_state(state_file, state)
    print(f"{path.name}: {state['status']}")
    return False


def run(
    input_dir: Path, output_dir: Path, wordlists: list[Path],
    seconds_per_file: float, download: bool,
) -> int:
    if input_dir == output_dir:
        print("Eingabe- und Ausgabeordner müssen verschieden sein")
        return 2
    files = sorted(
        (p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() in {".doc", ".docx"}),
        key=lambda p: p.name.lower(),
    )
    if not files:
        print("Keine .doc- oder .docx-Dateien gefunden")
        return 2
    if shutil.which("hashcat") is None:
        print("hashcat ist nicht installiert oder nicht im PATH")
        return 2
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_dir = output_dir / ".docdecrypt"
    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_dir.chmod(0o700)
    downloaded, errors = available_wordlists(private_dir / "lists", download)
    for error in errors:
        print(f"Wortliste nicht verfügbar: {error}")
    own_lists = [p.resolve() for p in wordlists]
    successes = 0
    for path in files:
        try:
            successes += _process_file(
                path, output_dir, private_dir, own_lists, downloaded, seconds_per_file,
            )
        except UnsupportedDocumentError as exc:
            print(f"{path.name}: {exc}")
        except KeyboardInterrupt:
            print("\nSuche unterbrochen; beim nächsten Aufruf wird sie fortgesetzt")
            return 130
    print(f"Fertig: {successes}/{len(files)} Dateien ohne Passwortschutz im Ausgabeordner")
    return 0 if successes == len(files) else 1
