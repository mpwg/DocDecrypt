# iForgotMyPassword

iForgotMyPassword ist eine native macOS-App für Apple Silicon. Sie sucht das
Passwort einer verschlüsselten Word-Datei (`.doc` oder `.docx`) und zeigt es an.
Die App entschlüsselt das Dokument nicht und legt keine entschlüsselte Kopie an.
Eine Suche kann dauern oder ohne Treffer enden.

## Verwendung

1. Die App öffnen und eine Datei auswählen oder auf das Fenster ziehen.
2. Die maximale Suchdauer einstellen (1 bis 1440 Minuten, Standard: 60).
3. Die Suche starten. Vor einem Download größerer Wortlisten fragt die App nach.
   Auch ohne Download kann sie mit vorhandenen Listen und Dateinamen-Kandidaten suchen.
4. Ein gefundenes Passwort kopieren. Danach fragt die App, ob es zu
   **Known Passwords** hinzugefügt werden soll. Standard ist **Nein**.

Nur nach Zustimmung speichert die App ein Passwort im macOS-Schlüsselbund.
Gespeicherte Passwörter werden bei späteren Dateien zuerst geprüft. Suchstände,
Prüfdaten, Wortlisten und der private hashcat-Cache liegen unter
`~/Library/Application Support/iForgotMyPassword/`. Die Originaldatei bleibt
unverändert. Der Suchstand ermöglicht eine Fortsetzung nach dem Anhalten oder
nach Ablauf der eingestellten Zeit. Bei einem Fund wird das Passwort selbst
nicht im Suchstand gespeichert.

## Bauen

Benötigt werden Xcode 27 und auf dem **Build-Mac** Homebrew-Pakete für hashcat
7.1.2, minizip und xxhash. Die fertige App enthält diese Laufzeitbestandteile;
auf dem Ziel-Mac sind weder Homebrew noch Python nötig. Das Xcode-Projekt ist
[iForgotMyPassword.xcodeproj](iForgotMyPassword/iForgotMyPassword.xcodeproj).
Zielplattform ist macOS 14 oder neuer auf Apple Silicon. Xcode baut und signiert
die App für die lokale Ausführung. Eine Verteilung außerhalb des eigenen Macs
erfordert einen separaten Signierungs- und Notarisierungsschritt.

Der Build-Schritt [bundle-hashcat.sh](scripts/bundle-hashcat.sh) übernimmt die
benötigten hashcat-Module, Kernel, Bibliotheken und Lizenzhinweise in das
App-Paket. Er erwartet hashcat 7.1.2 unter
`/opt/homebrew/Cellar/hashcat/7.1.2`. Vor einem Build muss dieses Paket auf dem
Build-Mac vorhanden sein.

## Tests

Die Xcode-Scheme `iForgotMyPassword` enthält Unit- und UI-Tests. Die Tests
prüfen die Word-Prüfdaten, einen vollständigen Passwortfund ohne entschlüsselte
Ausgabedatei, die Verwendung eines bewusst gespeicherten Passworts und die
anfänglichen Bedienelemente. Die `.docx`-Beispiele wurden für dieses Projekt
erzeugt. Die `.doc`-Testdatei stammt aus den
[Testdaten von msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool/tree/master/tests/inputs);
deren MIT-Lizenz und Hinweise liegen bei der Testdatei.

## Grenzen

Unterstützt werden die Office-Verschlüsselungsverfahren, für die die App
hashcat-Modi 9400, 9500, 9600, 9700 und 9800 enthält. Unverschlüsselte Dateien,
XOR-Verschleierung und andere Office-Formate meldet sie als nicht unterstützt.
Die Passwortsuche erfolgt lokal; nur der ausdrücklich bestätigte
Wortlisten-Download verbindet sich mit SecLists und Kali Wordlists.
