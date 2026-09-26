"""Ablauf der Wiederherstellung."""

from pathlib import Path


def run(
    input_dir: Path, output_dir: Path, wordlists: list[Path],
    seconds_per_file: float, download: bool,
) -> int:
    raise NotImplementedError("Die Suchmaschine folgt im nächsten Commit")
