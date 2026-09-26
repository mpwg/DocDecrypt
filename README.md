# DocDecrypt

DocDecrypt versucht, passwortgeschützte Word-Dateien (`.doc` und `.docx`) aus
einem Ordner lokal zu entschlüsseln. Originale bleiben erhalten. Die Suche
speichert ihren Fortschritt und läuft pro Datei standardmäßig höchstens eine
Stunde je Aufruf. Ein starkes oder unbekanntes Passwort lässt sich möglicherweise
nicht finden.

## Installation

Python 3.10 oder neuer und [hashcat](https://hashcat.net/hashcat/) werden benötigt.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

## Verwendung

```sh
.venv/bin/docdecrypt samples
.venv/bin/docdecrypt /pfad/zu/word-dateien --ausgabe /pfad/zu/ergebnissen
.venv/bin/docdecrypt samples --wortliste /pfad/eigene-liste.txt --stunden-pro-datei 2
.venv/bin/docdecrypt samples --ohne-download
```

Der Ausgabeordner ist standardmäßig `./recovered`. Beim ersten Aufruf lädt das
Programm dort unter `.docdecrypt/lists` zwei Listen aus SecLists und `rockyou`
aus dem Kali-Wordlists-Projekt. Die Downloads sind auf feste Quellversionen und
SHA-256-Prüfsummen festgelegt. Mit `--ohne-download` verwendet es nur vorhandene
Listen sowie Kandidaten aus den Dateinamen. Zusätzliche Listen können mehrfach
mit `--wortliste` angegeben werden. Eine Liste enthält ein Passwort je Zeile.

Die Suche versucht bekannte Passwörter, eigene und erzeugte Listen, allgemeine
Listen, Regelvarianten, Zahlen- und Jahresanhänge, Masken und bei geeigneten
alten Word-Dateien RC4-Kollisionsverfahren. Sie kann mit Strg+C unterbrochen
werden. Ein erneuter Aufruf mit demselben Ausgabeordner setzt die Suche fort.
Hashcat benötigt beim ersten Start möglicherweise zusätzliche Zeit für seine
GPU-Initialisierung.

Entschlüsselte Dateien liegen direkt im Ausgabeordner. Der Unterordner
`.docdecrypt` enthält Passwörter, Prüfdaten und Sitzungsstände; er erhält auf
Unix-Systemen nur Zugriff für den aktuellen Benutzer. Er gehört nicht in ein
öffentliches Repository. Die mitgelieferte `.gitignore` nimmt den Standardordner,
Word-Dateien, Listen und Sitzungsdateien von Git aus. Für selbst gewählte
Ausgabeordner innerhalb anderer Repositories ist deren Git-Konfiguration
ebenfalls zu prüfen.

Rückgabewert `0` bedeutet, dass alle Dateien unverschlüsselt im Ausgabeordner
liegen. `1` bedeutet, dass mindestens eine Datei noch nicht entschlüsselt wurde.
`2` bezeichnet einen Eingabe- oder Werkzeugfehler.

## Tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Die Tests erzeugen eigene Word-Dateien und verwenden keine privaten Beispiele.
