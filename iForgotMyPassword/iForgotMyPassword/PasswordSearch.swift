import CryptoKit
import Foundation
import Security

enum SearchResult {
    case found(String)
    case paused
    case exhausted
}

struct SearchStage: Codable {
    let name: String
    let attack: Int
    let inputs: [String]
    let rule: Bool
    let increment: Bool

    var key: String {
        let encoded = (try? JSONEncoder().encode(self)) ?? Data()
        return SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined().prefix(16).description
    }
}

struct SearchState: Codable {
    var completed: Set<String> = []
}

enum SearchFiles {
    static var root: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("iForgotMyPassword", isDirectory: true)
    }
    static func privateDirectory() throws -> URL {
        let url = root.appendingPathComponent("Search", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return url
    }
    static func fileID(_ url: URL) throws -> String {
        var hasher = SHA256()
        hasher.update(data: Data(url.standardizedFileURL.path.utf8))
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        while let block = try handle.read(upToCount: 1024 * 1024), !block.isEmpty {
            hasher.update(data: block)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined().prefix(24).description
    }
    static func save(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

final class KnownPasswords {
    private let service: String
    private let account = "passwords"

    init(service: String = "at.mat.iForgotMyPassword.known") {
        self.service = service
    }

    func all() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let passwords = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return passwords
    }

    func add(_ password: String) throws {
        var values = all()
        guard !values.contains(password) else { return }
        values.append(password)
        let data = try JSONEncoder().encode(values)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var creation = query
            creation[kSecValueData as String] = data
            creation[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            guard SecItemAdd(creation as CFDictionary, nil) == errSecSuccess else {
                throw DocumentError.unsupported("Passwort konnte nicht im Schlüsselbund gespeichert werden")
            }
        } else if status != errSecSuccess {
            throw DocumentError.unsupported("Passwort konnte nicht im Schlüsselbund gespeichert werden")
        }
    }

    func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

struct WordlistSource {
    let name: String
    let url: URL
    let sha256: String
    let compressed: Bool
    let contentSHA256: String?
}

enum Wordlists {
    static let sources: [WordlistSource] = [
        .init(name: "seclists-10k.txt",
              url: URL(string: "https://raw.githubusercontent.com/danielmiessler/SecLists/49c9fcd20e0945f24ec854872f265eb3d13c3741/Passwords/Common-Credentials/10k-most-common.txt")!,
              sha256: "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce",
              compressed: false, contentSHA256: nil),
        .init(name: "seclists-100k.txt",
              url: URL(string: "https://raw.githubusercontent.com/danielmiessler/SecLists/49c9fcd20e0945f24ec854872f265eb3d13c3741/Passwords/Common-Credentials/Pwdb_top-100000.txt")!,
              sha256: "07f876a616f08fb2cc5c3e0ce04e4a6d1123380580472b0997baebc4e8226977",
              compressed: false, contentSHA256: nil),
        .init(name: "rockyou.txt",
              url: URL(string: "https://gitlab.com/kalilinux/packages/wordlists/-/raw/7d461801f64424c8a5004238f07c2ece584e647b/rockyou.txt.gz")!,
              sha256: "ded2d962815e1256df8f3a0d25173c4b21b6eee636117c36999246725a6d8f9f",
              compressed: true,
              contentSHA256: "16035fea7742cb0561c513de1d946eda5716d7de294e6c732449740096686173")
    ]

    static func cached() -> [URL] {
        let folder = SearchFiles.root.appendingPathComponent("Lists")
        return sources.compactMap { source in
            let file = folder.appendingPathComponent(source.name)
            return FileManager.default.fileExists(atPath: file.path) ? file : nil
        }
    }

    static func downloadMissing(status: (String) -> Void) throws -> [URL] {
        let folder = SearchFiles.root.appendingPathComponent("Lists")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        var available: [URL] = []
        for source in sources {
            let target = folder.appendingPathComponent(source.name)
            let expected = source.contentSHA256 ?? source.sha256
            if let existing = try? Data(contentsOf: target), digest(existing) == expected {
                available.append(target)
                continue
            }
            status("Lade \(source.name)")
            let downloaded = try Data(contentsOf: source.url)
            guard downloaded.count <= 200 * 1024 * 1024, digest(downloaded) == source.sha256 else {
                throw DocumentError.unsupported("Download von \(source.name) ist beschädigt")
            }
            if source.compressed {
                let archive = folder.appendingPathComponent(UUID().uuidString + ".gz")
                try SearchFiles.save(downloaded, to: archive)
                defer { try? FileManager.default.removeItem(at: archive) }
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
                process.arguments = ["-dc", archive.path]
                let output = FileManager.default.createFile(atPath: target.path, contents: nil)
                guard output, let handle = try? FileHandle(forWritingTo: target) else {
                    throw DocumentError.unsupported("Wortliste kann nicht gespeichert werden")
                }
                process.standardOutput = handle
                try process.run()
                process.waitUntilExit()
                try handle.close()
                guard process.terminationStatus == 0,
                      let uncompressed = try? Data(contentsOf: target),
                      uncompressed.count <= 500 * 1024 * 1024,
                      digest(uncompressed) == expected else {
                    try? FileManager.default.removeItem(at: target)
                    throw DocumentError.unsupported("Wortliste \(source.name) ist beschädigt")
                }
            } else {
                try SearchFiles.save(downloaded, to: target)
            }
            available.append(target)
        }
        return available
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

final class PasswordSearch {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    private let knownPasswords: KnownPasswords
    private let runtimeID = UUID().uuidString

    init(knownPasswords: KnownPasswords = KnownPasswords()) {
        self.knownPasswords = knownPasswords
    }

    deinit {
        let runtime = SearchFiles.root.appendingPathComponent("Search/Runtime-\(runtimeID)")
        try? FileManager.default.removeItem(at: runtime)
    }

    func cancel() {
        lock.lock()
        cancelled = true
        process?.interrupt()
        lock.unlock()
    }

    private func isCancelled() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    private func executable() throws -> URL {
        guard let bundle = Bundle.main.executableURL?.deletingLastPathComponent()
            .appendingPathComponent("hashcat_bin"),
              let contents = Bundle.main.resourceURL?.deletingLastPathComponent(),
              FileManager.default.isExecutableFile(atPath: bundle.path) else {
            throw DocumentError.unsupported("hashcat fehlt im App-Paket")
        }
        // hashcat writes its kernel cache beside its executable. Run a private
        // copy so the signed app bundle remains immutable.
        let runtime = try SearchFiles.privateDirectory().appendingPathComponent("Runtime-\(runtimeID)")
        let bin = runtime.appendingPathComponent("MacOS")
        let frameworks = runtime.appendingPathComponent("Frameworks")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: frameworks, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let target = bin.appendingPathComponent("hashcat_bin")
        if !FileManager.default.fileExists(atPath: target.path) {
            try FileManager.default.copyItem(at: bundle, to: target)
        }
        let links: [(URL, URL)] = [
            (bin.appendingPathComponent("OpenCL"), contents.appendingPathComponent("Resources/hashcat/OpenCL")),
            (bin.appendingPathComponent("modules"), contents.appendingPathComponent("Resources/hashcat/modules")),
            (frameworks.appendingPathComponent("libminizip.1.dylib"), contents.appendingPathComponent("Frameworks/libminizip.1.dylib")),
            (frameworks.appendingPathComponent("libxxhash.0.dylib"), contents.appendingPathComponent("Frameworks/libxxhash.0.dylib"))
        ]
        for (link, destination) in links where !FileManager.default.fileExists(atPath: link.path) {
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: destination)
        }
        return target
    }

    private func run(_ arguments: [String], input: String? = nil) throws -> (Int32, String) {
        let executable = try executable()
        let process = Process()
        process.executableURL = executable
        process.arguments = ["--logfile-disable"] + arguments
        var environment = ProcessInfo.processInfo.environment
        if let resources = Bundle.main.resourceURL {
            environment["XDG_DATA_HOME"] = resources.path
        }
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        if let input {
            let pipe = Pipe()
            process.standardInput = pipe
            try process.run()
            pipe.fileHandleForWriting.write(Data(input.utf8))
            try pipe.fileHandleForWriting.close()
        } else {
            try process.run()
        }
        lock.lock()
        self.process = process
        if cancelled { process.interrupt() }
        lock.unlock()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        lock.lock()
        self.process = nil
        lock.unlock()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    func search(_ url: URL, minutes: Int, download: Bool, status: (String) -> Void) throws -> SearchResult {
        guard (1...1440).contains(minutes) else {
            throw DocumentError.unsupported("Die Suchdauer muss zwischen 1 und 1440 Minuten liegen")
        }
        let hasAccess = url.startAccessingSecurityScopedResource()
        defer { if hasAccess { url.stopAccessingSecurityScopedResource() } }
        let office = try OfficeHash.extract(url)
        let root = try SearchFiles.privateDirectory()
        let id = try SearchFiles.fileID(url)
        let stateURL = root.appendingPathComponent("\(id).json")
        var state = (try? JSONDecoder().decode(SearchState.self, from: Data(contentsOf: stateURL))) ?? SearchState()
        let hashURL = root.appendingPathComponent("\(id).hash")
        try SearchFiles.save(Data((office.value + "\n").utf8), to: hashURL)
        let deadline = Date().addingTimeInterval(Double(minutes) * 60)

        for password in knownPasswords.all() {
            if isCancelled() { return .paused }
            status("Prüfe bekannte Passwörter")
            let result = try run(["-m", String(office.mode), "-a", "0", "--potfile-disable",
                                  "--quiet", hashURL.path], input: password + "\n")
            if result.0 == 0, result.1.contains(password) { return .found(password) }
        }
        let lists: [URL]
        if download {
            lists = try Wordlists.downloadMissing(status: status)
        } else {
            lists = Wordlists.cached()
        }
        let context = root.appendingPathComponent("\(id).wordlist")
        let tokens = url.deletingPathExtension().lastPathComponent
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        let bases = Set(tokens.filter { $0.count >= 3 } + ["password", "passwort", "word", "test", "1998", "1999", "2000"])
        var candidates = Set<String>()
        for token in bases {
            for form in [token, token.lowercased(), token.capitalized] {
                candidates.insert(form)
                for suffix in ["1", "12", "123", "!", "98", "99", "1998", "1999", "2000"] {
                    candidates.insert(form + suffix)
                }
            }
        }
        try SearchFiles.save(Data((candidates.sorted().joined(separator: "\n") + "\n").utf8), to: context)
        let dictionaries = [context] + lists
        var stages = dictionaries.map {
            SearchStage(name: "Wörterbuch: \($0.lastPathComponent)", attack: 0,
                        inputs: [$0.path], rule: false, increment: false)
        }
        let rules = Bundle.main.resourceURL?.appendingPathComponent("best-effort.rule")
        if rules.map({ FileManager.default.fileExists(atPath: $0.path) }) == true {
            stages += dictionaries.prefix(3).map {
                SearchStage(name: "Regeln: \($0.lastPathComponent)", attack: 0,
                            inputs: [$0.path], rule: true, increment: false)
            }
        }
        for dictionary in dictionaries.prefix(2) {
            stages.append(.init(name: "Zahlenanhang: \(dictionary.lastPathComponent)", attack: 6,
                                inputs: [dictionary.path, "?d?d"], rule: false, increment: false))
            stages.append(.init(name: "Jahresanhang: \(dictionary.lastPathComponent)", attack: 6,
                                inputs: [dictionary.path, "19?d?d"], rule: false, increment: false))
        }
        stages += [
            .init(name: "Ziffern 1–8", attack: 3, inputs: ["?d?d?d?d?d?d?d?d"], rule: false, increment: true),
            .init(name: "Kleinbuchstaben 1–6", attack: 3, inputs: ["?l?l?l?l?l?l"], rule: false, increment: true),
            .init(name: "ASCII 1–4", attack: 3, inputs: ["?a?a?a?a"], rule: false, increment: true)
        ]
        for stage in stages where !state.completed.contains(stage.key) {
            if isCancelled() || Date() >= deadline { return .paused }
            status(stage.name)
            let restore = root.appendingPathComponent("\(id)-\(stage.key).restore")
            let output = root.appendingPathComponent("\(id)-\(stage.key).result")
            defer { try? FileManager.default.removeItem(at: output) }
            let session = "ifmp-\(id.prefix(10))-\(stage.key)"
            var arguments: [String]
            if FileManager.default.fileExists(atPath: restore.path) {
                arguments = ["--restore", "--session", session, "--restore-file-path", restore.path]
            } else {
                arguments = ["-m", String(office.mode), "-a", String(stage.attack),
                             "--session", session, "--restore-file-path", restore.path,
                             "--potfile-disable", "--runtime", String(max(1, Int(deadline.timeIntervalSinceNow))),
                             "--quiet", "--outfile", output.path, "--outfile-format", "2", hashURL.path]
                if stage.rule, let rules { arguments += ["-r", rules.path] }
                if stage.increment { arguments += ["--increment", "--increment-min", "1"] }
                arguments += stage.inputs
            }
            let result = try run(arguments)
            if let raw = try? Data(contentsOf: output), !raw.isEmpty,
               let password = String(data: raw, encoding: .utf8)?.trimmingCharacters(in: .newlines),
               !password.isEmpty {
                return .found(password)
            }
            if isCancelled() || Date() >= deadline || FileManager.default.fileExists(atPath: restore.path) {
                return .paused
            }
            guard result.0 == 0 || result.0 == 1 else {
                throw DocumentError.unsupported(result.1.split(separator: "\n").last.map(String.init) ?? "hashcat-Fehler")
            }
            state.completed.insert(stage.key)
            try SearchFiles.save(JSONEncoder().encode(state), to: stateURL)
        }
        return .exhausted
    }
}
