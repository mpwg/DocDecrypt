# iForgotMyPassword

`iForgotMyPassword` is a native macOS app for recovering the password of an
encrypted Microsoft Word document that you are authorized to access. It supports
legacy `.doc` and modern `.docx` files, runs password searches locally on Apple
Silicon, and leaves the original document untouched.

The app extracts only the encryption verification data required to test password
candidates. It does **not** decrypt the document or write a decrypted copy.

> Use this software only for documents you own or are explicitly authorized to
> access. Password recovery may take a long time and is not guaranteed to find a
> password.

## Highlights

- Native SwiftUI app for macOS 14+ on Apple Silicon
- Drag-and-drop or file-picker workflow for `.doc` and `.docx`
- Fully local password testing; no document contents are uploaded
- Optional, checksum-verified word-list downloads
- Searches known passwords first, then filename-based candidates, dictionaries,
  rules, suffixes, and small brute-force spaces
- Pause and resume support, including after the configured time limit
- Optional storage of found passwords in the user's macOS Keychain

## Architecture

```text
Encrypted Word file
        │
        ▼
OfficeHash extracts encryption verification data
        │
        ▼
PasswordSearch builds and resumes local search stages
        │
        ├── known passwords in the macOS Keychain
        ├── filename-derived candidates
        ├── cached or user-approved word lists and rules
        └── limited mask attacks
        │
        ▼
Bundled hashcat tests candidates against the verification data
        │
        ▼
Verified password shown in the app
```

The app is split into a small set of focused components:

- **SwiftUI interface (`ContentView`)** manages file selection, search duration,
  progress, pausing, and the consent prompts for downloads and Keychain storage.
- **Office parser (`OfficeHash`)** reads the `EncryptionInfo` stream in modern
  Office containers and the relevant Word streams in legacy OLE files. It
  converts their verification data to a hashcat-compatible hash.
- **Search coordinator (`PasswordSearch`)** creates the candidate stages,
  persists their progress, invokes hashcat, and independently verifies every
  candidate hashcat reports.
- **Local storage** keeps resumable search state and caches in Application
  Support, while intentionally saved passwords live in the macOS Keychain.
- **Bundled runtime** packages hashcat, selected modules, kernels, support
  libraries, and the project rule file within the application bundle at build
  time. The executable runs from a private runtime copy so the signed app bundle
  is not modified.

## Using the app

1. Open the app and choose an encrypted `.doc` or `.docx` file, or drop one onto
   its window.
2. Set a search duration between 1 and 1,440 minutes (60 minutes by default).
3. Select **Start Search**. If the bundled word lists are not already cached,
   choose whether to download them. Searching without a download remains
   available.
4. Wait for a result, pause the search, or resume a paused search later.
5. Copy a discovered password. If desired, confirm that it should be added to
   **Known Passwords** for future searches.

Only an explicit confirmation stores a found password. Known passwords are held
in the macOS Keychain and are checked before any other search stage.

## Privacy and local data

Document data and password candidates stay on the Mac. The app makes a network
request only when you explicitly approve downloading missing word lists from the
pinned SecLists and Kali Wordlists sources. Downloads are checked against their
expected SHA-256 hashes before being used.

The app keeps private search data in:

```text
~/Library/Application Support/iForgotMyPassword/
```

This contains the search state, verification hashes, generated candidate lists,
downloaded word lists, and a private hashcat runtime/cache. Files are created
with owner-only permissions where supported. The resume state never stores a
recovered password. The original document is never modified.

## Supported encryption

The app supports the Office encryption formats handled by its bundled hashcat
modes:

| File type | Supported modes |
| --- | --- |
| Modern Office encryption (`.docx`) | 9400, 9500, 9600 |
| Legacy Office encryption (`.doc`) | 9700, 9800 |
| Legacy RC4 collision search | 9710, 9720 |

Unencrypted documents, legacy XOR obfuscation, unsupported Office encryption
variants, malformed files, and Office formats other than `.doc`/`.docx` are
reported as unsupported.

## Limitations

- This is a password-recovery tool, not a guarantee of recovery. Strong, random,
  long passwords can be impractical to search.
- The configured duration limits each run. A paused search can be resumed, but
  the remaining candidate space may still be very large.
- The included mask attacks are intentionally limited (digits up to 8
  characters, lowercase letters up to 6, and ASCII up to 4). They do not cover
  every possible password.
- Search speed depends on the document's encryption scheme, password complexity,
  available hardware, and the chosen word lists. Apple Silicon is required.
- A found password is shown but the app does not decrypt or export the file.
- Searches use hashcat and its included runtime components. The project license
  applies to this project's source; bundled and downloaded third-party material
  remains subject to its own license terms.

## Build from source

### Requirements

- macOS 14 or later on an Apple Silicon Mac
- Xcode with the macOS 14 SDK or later
- Homebrew packages for the pinned hashcat release, `minizip`, and `xxhash`
- hashcat **7.1.2** installed at
  `/opt/homebrew/Cellar/hashcat/7.1.2`

The project is [iForgotMyPassword.xcodeproj](iForgotMyPassword/iForgotMyPassword.xcodeproj).
Open it in Xcode, select the `iForgotMyPassword` scheme, and build/run it. Its
build phase runs [bundle-hashcat.sh](scripts/bundle-hashcat.sh), which copies the
required hashcat executable, modules, kernels, libraries, rule file, and
third-party license notice into the app bundle.

The resulting app is signed for local development. Distribution outside the
build machine requires your own Developer ID signing and notarization process.

## Tests

The `iForgotMyPassword` Xcode scheme includes unit and UI tests. They cover
Office verification-data extraction, a complete password recovery without a
decrypted output file, use of a deliberately stored known password, and the
initial UI controls.

The `.docx` fixtures were created for this project. The `.doc` fixture originates
from [msoffcrypto-tool test data](https://github.com/nolze/msoffcrypto-tool/tree/master/tests/inputs);
its accompanying MIT license and notice are retained alongside that fixture.

## Project layout

```text
iForgotMyPassword/
  iForgotMyPassword/       App UI, Office parsing, and search orchestration
  iForgotMyPasswordTests/  Unit tests and encrypted document fixtures
  iForgotMyPasswordUITests/UI tests
resources/                 hashcat rule file
scripts/                   App-bundle assembly for hashcat
```

## License

This project's source code is licensed under the [MIT License](LICENSE).
See the notices included with bundled or fixture dependencies for their
respective terms.
