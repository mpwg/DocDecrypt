import Foundation

enum DocumentError: LocalizedError {
    case unsupported(String)
    var errorDescription: String? {
        switch self { case .unsupported(let message): message }
    }
}

private extension Data {
    func number(_ offset: Int, _ count: Int) throws -> UInt64 {
        guard offset >= 0, count > 0, count <= 8, offset <= self.count - count else {
            throw DocumentError.unsupported("Beschädigte Word-Datei")
        }
        return (0..<count).reduce(UInt64(0)) { $0 | (UInt64(self[offset + $1]) << (8 * $1)) }
    }
    func part(_ offset: Int, _ count: Int) throws -> Data {
        guard offset >= 0, count >= 0, offset <= self.count - count else {
            throw DocumentError.unsupported("Beschädigte Word-Datei")
        }
        return self.subdata(in: offset..<(offset + count))
    }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// Reads only the streams required for Office password verification.
struct CompoundFile {
    private let bytes: Data
    private let sectorSize: Int
    private let miniSize: Int
    private let cutoff: Int
    private let fat: [UInt32]
    private let miniFat: [UInt32]
    private let directory: [(name: String, first: UInt32, size: Int)]
    private let miniStream: Data

    init(_ bytes: Data) throws {
        guard bytes.count >= 512, Array(bytes.prefix(8)) == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] else {
            throw DocumentError.unsupported("Kein unterstützter Word-Container")
        }
        self.bytes = bytes
        let shift = Int(try bytes.number(30, 2))
        let miniShift = Int(try bytes.number(32, 2))
        guard shift == 9 || shift == 12, miniShift == 6 else {
            throw DocumentError.unsupported("Nicht unterstützte OLE-Sektorgröße")
        }
        let sectorSize = 1 << shift
        let miniSize = 1 << miniShift
        let cutoff = Int(try bytes.number(56, 4))

        func sector(_ id: UInt32) throws -> Data {
            let offset = (Int(id) + 1) * sectorSize
            return try bytes.part(offset, sectorSize)
        }
        var fatIDs: [UInt32] = []
        for index in 0..<109 {
            let id = UInt32(try bytes.number(76 + index * 4, 4))
            if id < 0xfffffffa { fatIDs.append(id) }
        }
        var next = UInt32(try bytes.number(68, 4))
        let difatCount = Int(try bytes.number(72, 4))
        for _ in 0..<min(difatCount, bytes.count / sectorSize) {
            guard next < 0xfffffffa else { break }
            let data = try sector(next)
            for index in 0..<(sectorSize / 4 - 1) {
                let id = UInt32(try data.number(index * 4, 4))
                if id < 0xfffffffa { fatIDs.append(id) }
            }
            next = UInt32(try data.number(sectorSize - 4, 4))
        }
        let fatCount = Int(try bytes.number(44, 4))
        var fatEntries: [UInt32] = []
        for id in fatIDs.prefix(fatCount) {
            let data = try sector(id)
            for index in 0..<(sectorSize / 4) {
                fatEntries.append(UInt32(try data.number(index * 4, 4)))
            }
        }

        func chain(_ first: UInt32, _ table: [UInt32], _ unit: Int, _ source: Data, _ limit: Int? = nil) throws -> Data {
            var result = Data()
            var id = first
            var seen = Set<UInt32>()
            while id < 0xfffffffa && (limit == nil || result.count < limit!) {
                guard Int(id) < table.count, seen.insert(id).inserted else {
                    throw DocumentError.unsupported("Beschädigte OLE-Sektorkette")
                }
                let offset = unit == sectorSize ? (Int(id) + 1) * unit : Int(id) * unit
                result.append(try source.part(offset, unit))
                id = table[Int(id)]
            }
            if let limit {
                guard result.count >= limit else { throw DocumentError.unsupported("Unvollständiger OLE-Stream") }
                return Data(result.prefix(limit))
            }
            return result
        }
        let dirFirst = UInt32(try bytes.number(48, 4))
        let dirData = try chain(dirFirst, fatEntries, sectorSize, bytes)
        var entries: [(name: String, first: UInt32, size: Int)] = []
        for offset in stride(from: 0, through: max(0, dirData.count - 128), by: 128) {
            let length = Int(try dirData.number(offset + 64, 2))
            let kind = UInt8(try dirData.number(offset + 66, 1))
            guard (kind == 2 || kind == 5), length >= 2, length <= 64 else { continue }
            let nameBytes = try dirData.part(offset, length - 2)
            let name = String(data: nameBytes, encoding: .utf16LittleEndian) ?? ""
            let first = UInt32(try dirData.number(offset + 116, 4))
            let size = Int(try dirData.number(offset + 120, 8))
            entries.append((name, first, size))
        }
        let miniFirst = UInt32(try bytes.number(60, 4))
        let miniCount = Int(try bytes.number(64, 4))
        var miniEntries: [UInt32] = []
        if miniCount > 0 {
            let data = try chain(miniFirst, fatEntries, sectorSize, bytes, miniCount * sectorSize)
            for index in 0..<(data.count / 4) {
                miniEntries.append(UInt32(try data.number(index * 4, 4)))
            }
        }
        let miniStream: Data
        if let root = entries.first(where: { $0.name == "Root Entry" }), root.size > 0 {
            miniStream = try chain(root.first, fatEntries, sectorSize, bytes, root.size)
        } else {
            miniStream = Data()
        }
        self.sectorSize = sectorSize
        self.miniSize = miniSize
        self.cutoff = cutoff
        self.fat = fatEntries
        self.miniFat = miniEntries
        self.directory = entries
        self.miniStream = miniStream
    }

    func stream(_ name: String) throws -> Data {
        guard let entry = directory.first(where: { $0.name == name }) else {
            throw DocumentError.unsupported("Word-Stream „\(name)“ fehlt")
        }
        guard entry.size > 0, entry.size <= bytes.count else {
            throw DocumentError.unsupported("Ungültiger Word-Stream")
        }
        let useMini = entry.size < cutoff
        let table = useMini ? miniFat : fat
        let unit = useMini ? miniSize : sectorSize
        let source = useMini ? miniStream : bytes
        var result = Data()
        var id = entry.first
        var seen = Set<UInt32>()
        while id < 0xfffffffa && result.count < entry.size {
            guard Int(id) < table.count, seen.insert(id).inserted else {
                throw DocumentError.unsupported("Beschädigte Word-Streamkette")
            }
            let offset = useMini ? Int(id) * unit : (Int(id) + 1) * unit
            result.append(try source.part(offset, unit))
            id = table[Int(id)]
        }
        guard result.count >= entry.size else { throw DocumentError.unsupported("Unvollständiger Word-Stream") }
        return Data(result.prefix(entry.size))
    }
}

private final class EncryptedKeyParser: NSObject, XMLParserDelegate {
    var attributes: [String: String]?
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String]) {
        if elementName == "encryptedKey" && attributeDict["spinCount"] != nil {
            attributes = attributeDict
        }
    }
}

struct OfficeHash {
    let value: String
    let mode: Int

    static func extract(_ url: URL) throws -> OfficeHash {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        if data.starts(with: [0x50, 0x4b]) {
            throw DocumentError.unsupported("Die Datei ist nicht passwortverschlüsselt")
        }
        let compound = try CompoundFile(data)
        if url.pathExtension.lowercased() == "docx" {
            return try modern(compound.stream("EncryptionInfo"))
        }
        guard url.pathExtension.lowercased() == "doc" else {
            throw DocumentError.unsupported("Nur .doc und .docx werden unterstützt")
        }
        let word = try compound.stream("WordDocument")
        let flags = UInt8(try word.number(11, 1))
        guard flags & 1 != 0 else {
            throw DocumentError.unsupported("Die Datei ist nicht passwortverschlüsselt")
        }
        guard flags & 0x80 == 0 else {
            throw DocumentError.unsupported("Alte XOR-Verschleierung wird nicht unterstützt")
        }
        let tableName = flags & 2 == 0 ? "0Table" : "1Table"
        return try legacy(compound.stream(tableName))
    }

    private static func modern(_ data: Data) throws -> OfficeHash {
        let major = try data.number(0, 2)
        let minor = try data.number(2, 2)
        if major == 4 && minor == 4 {
            guard try data.number(4, 4) == 0x40 else {
                throw DocumentError.unsupported("Nicht unterstützte Office-Verschlüsselung")
            }
            let parser = EncryptedKeyParser()
            let xml = XMLParser(data: try data.part(8, data.count - 8))
            xml.delegate = parser
            guard xml.parse(), let attrs = parser.attributes,
                  let spins = Int(attrs["spinCount"] ?? ""),
                  let bits = Int(attrs["keyBits"] ?? ""),
                  let saltSize = Int(attrs["saltSize"] ?? ""),
                  let salt = Data(base64Encoded: attrs["saltValue"] ?? ""),
                  let verifier = Data(base64Encoded: attrs["encryptedVerifierHashInput"] ?? ""),
                  let verifierHash = Data(base64Encoded: attrs["encryptedVerifierHashValue"] ?? "") else {
                throw DocumentError.unsupported("Ungültige Office-Prüfdaten")
            }
            let year: Int
            switch attrs["hashAlgorithm"] {
            case "SHA1": year = 2010
            case "SHA512": year = 2013
            default: throw DocumentError.unsupported("Nicht unterstützter Office-Hash")
            }
            guard attrs["cipherAlgorithm"] == "AES" else {
                throw DocumentError.unsupported("Nicht unterstützte Office-Chiffre")
            }
            let value = "$office$*\(year)*\(spins)*\(bits)*\(saltSize)*\(salt.hex)*\(verifier.hex)*\(verifierHash.hex.prefix(64))"
            return OfficeHash(value: value, mode: year == 2010 ? 9500 : 9600)
        }
        let headerLength = Int(try data.number(8, 4))
        let verifierOffset = 12 + headerLength
        let bits = Int(try data.number(28, 4))
        let saltSize = Int(try data.number(verifierOffset, 4))
        let salt = try data.part(verifierOffset + 4, saltSize)
        let verifier = try data.part(verifierOffset + 4 + saltSize, 16)
        let hashSize = Int(try data.number(verifierOffset + 20 + saltSize, 4))
        let hash = try data.part(verifierOffset + 24 + saltSize, min(32, hashSize))
        let value = "$office$*2007*\(hashSize)*\(bits)*\(saltSize)*\(salt.hex)*\(verifier.hex)*\(hash.hex)"
        return OfficeHash(value: value, mode: 9400)
    }

    private static func legacy(_ data: Data) throws -> OfficeHash {
        let major = try data.number(0, 2)
        let minor = try data.number(2, 2)
        if major == 1 && minor == 1 {
            let salt = try data.part(4, 16)
            let verifier = try data.part(20, 16)
            let hash = try data.part(36, 16)
            return OfficeHash(value: "$oldoffice$1*\(salt.hex)*\(verifier.hex)*\(hash.hex)", mode: 9700)
        }
        guard (2...4).contains(major), minor == 2 else {
            throw DocumentError.unsupported("Nicht unterstützte .doc-Verschlüsselung")
        }
        let headerLength = Int(try data.number(8, 4))
        let bits = Int(try data.number(28, 4))
        let verifierOffset = 12 + headerLength
        let saltSize = Int(try data.number(verifierOffset, 4))
        let salt = try data.part(verifierOffset + 4, saltSize)
        let verifier = try data.part(verifierOffset + 4 + saltSize, 16)
        let hashSize = Int(try data.number(verifierOffset + 20 + saltSize, 4))
        let hash = try data.part(verifierOffset + 24 + saltSize, hashSize)
        let kind = bits == 40 ? 3 : 4
        guard bits == 40 || bits == 128 else {
            throw DocumentError.unsupported("Nicht unterstützte .doc-Schlüssellänge")
        }
        var value = "$oldoffice$\(kind)*\(salt.hex)*\(verifier.hex)*\(hash.hex)"
        if kind == 3 && data.count >= 544 {
            value += "*\((try data.part(512, 32)).hex)"
        }
        return OfficeHash(value: value, mode: 9800)
    }
}
