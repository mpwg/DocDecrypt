"""Kommandozeile für die lokale Dokumentwiederherstellung."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docdecrypt",
        description="Versucht, Word-Dateien in einem Ordner lokal zu entschlüsseln.",
    )
    parser.add_argument("eingabe", type=Path, help="Ordner mit .doc- und .docx-Dateien")
    parser.add_argument(
        "-o", "--ausgabe", type=Path, default=Path("recovered"),
        help="Ausgabeordner (Standard: ./recovered)",
    )
    parser.add_argument(
        "-w", "--wortliste", type=Path, action="append", default=[],
        help="Zusätzliche lokale Wortliste; mehrfach möglich",
    )
    parser.add_argument(
        "--stunden-pro-datei", type=float, default=1.0,
        help="Zeitgrenze je Datei und Aufruf (Standard: 1)",
    )
    parser.add_argument(
        "--ohne-download", action="store_true",
        help="Keine Wortlisten herunterladen",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.eingabe.is_dir():
        parser.error(f"Eingabeordner nicht gefunden: {args.eingabe}")
    if args.stunden_pro_datei <= 0:
        parser.error("--stunden-pro-datei muss größer als null sein")
    for wordlist in args.wortliste:
        if not wordlist.is_file():
            parser.error(f"Wortliste nicht gefunden: {wordlist}")
    from .runner import run

    return run(
        args.eingabe.resolve(), args.ausgabe.resolve(), args.wortliste,
        args.stunden_pro_datei * 3600, not args.ohne_download,
    )


if __name__ == "__main__":
    raise SystemExit(main())
