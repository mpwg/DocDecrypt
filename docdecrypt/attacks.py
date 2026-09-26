"""Gestufte hashcat-Angriffe mit Wiederaufnahme."""

from __future__ import annotations

import re
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


RULES = Path(__file__).parent / "rules" / "best-effort.rule"


@dataclass(frozen=True)
class Stage:
    name: str
    attack: int
    inputs: tuple[str, ...]
    mode: int | None = None
    collision: bool = False


def context_wordlist(path: Path, destination: Path) -> Path:
    tokens = {part for part in re.findall(r"[\wäöüÄÖÜß]+", path.stem) if len(part) >= 3}
    tokens.update({"password", "passwort", "word", "test", "1998", "1999", "2000"})
    candidates = set(tokens)
    for token in tokens:
        for form in {token, token.lower(), token.capitalize()}:
            candidates.add(form)
            for suffix in ("1", "12", "123", "!", "98", "99", "1998", "1999", "2000"):
                candidates.add(form + suffix)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.write_text("\n".join(sorted(candidates)) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination


def stages(
    own_lists: list[Path], context: Path, downloaded: list[Path],
    mode: int, hash_value: str,
) -> list[Stage]:
    ordered = [*own_lists, context, *downloaded]
    result = [Stage(f"Wörterbuch: {item.name}", 0, (str(item),)) for item in ordered]
    for item in [*own_lists, context, *downloaded[:2]]:
        result.append(Stage(f"Regeln: {item.name}", 0, (str(item),), mode=None))
    for item in [*own_lists, context, *downloaded[:1]]:
        result.extend([
            Stage(f"Zahlenanhang 2: {item.name}", 6, (str(item), "?d?d")),
            Stage(f"Jahresanhang: {item.name}", 6, (str(item), "19?d?d")),
        ])
    result.extend([
        Stage("Ziffern 1–8", 3, ("?d?d?d?d?d?d?d?d",)),
        Stage("Kleinbuchstaben 1–6", 3, ("?l?l?l?l?l?l",)),
        Stage("ASCII 1–4", 3, ("?a?a?a?a",)),
    ])
    if mode == 9700 and hash_value.startswith(("$oldoffice$0*", "$oldoffice$1*")):
        result.extend([
            Stage("RC4-Schlüssel", 3, ("?b?b?b?b?b",), mode=9710),
            Stage("RC4-Kollisionspasswort", 3, ("?a?a?a?a?a?a?a?a",), mode=9720, collision=True),
        ])
    return result


def _show_password(hash_file: Path, mode: int, potfile: Path) -> str | None:
    command = [
        "hashcat", "--show", "-m", str(mode), "--potfile-path", str(potfile),
        "--outfile-format", "2", str(hash_file),
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode or not result.stdout.strip():
        return None
    raw = result.stdout.splitlines()[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def execute_stage(
    stage: Stage, stage_key: str, hash_file: Path, default_mode: int,
    private_dir: Path, file_id: str, remaining: float,
) -> tuple[str | None, bool, str | None]:
    """Liefert (Passwort/Schlüssel, abgeschlossen, Fehler)."""
    mode = stage.mode or default_mode
    potfile = private_dir / "hashcat.potfile"
    restore = private_dir / f"{file_id}-{stage_key}.restore"
    session = f"dd-{file_id[:10]}-{stage_key}"
    found = _show_password(hash_file, mode, potfile)
    if found is not None:
        return found, True, None
    if restore.exists():
        command = ["hashcat", "--restore", "--session", session, "--restore-file-path", str(restore)]
    else:
        command = [
            "hashcat", "-m", str(mode), "-a", str(stage.attack),
            "--session", session, "--restore-file-path", str(restore),
            "--potfile-path", str(potfile), "--runtime", str(max(1, int(remaining))),
            "--quiet", str(hash_file),
        ]
        if stage.name.startswith("Regeln:"):
            command.extend(["-r", str(RULES)])
        if stage.name.startswith(("Ziffern", "Kleinbuchstaben", "ASCII", "RC4-Kollisionspasswort")):
            command.extend(["--increment", "--increment-min", "1"])
        if stage.name == "RC4-Schlüssel":
            command.append("--hex-charset")
        command.extend(stage.inputs)
    timed_out = False
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            _, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.send_signal(signal.SIGINT)
            try:
                _, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
        except KeyboardInterrupt:
            process.send_signal(signal.SIGINT)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise
    except OSError as exc:
        return None, False, str(exc)
    found = _show_password(hash_file, mode, potfile)
    if found is not None:
        return found, True, None
    if restore.exists():
        return None, False, None
    if timed_out:
        return None, False, None
    if process.returncode in (0, 1):
        return None, True, None
    reason = stderr.decode("utf-8", errors="replace").strip().splitlines()
    return None, False, reason[-1] if reason else f"hashcat beendet mit Code {process.returncode}"
