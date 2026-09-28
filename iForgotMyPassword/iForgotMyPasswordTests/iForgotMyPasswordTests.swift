import XCTest
@testable import iForgotMyPassword

final class iForgotMyPasswordTests: XCTestCase {
    private func fixture(_ name: String) -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/\(name)")
    }

    func testEncryptedDOCXExtractsHashWithoutWritingDocument() throws {
        let source = fixture("encrypted.docx")
        let before = try FileManager.default.contentsOfDirectory(
            at: source.deletingLastPathComponent(), includingPropertiesForKeys: nil)
        let hash = try OfficeHash.extract(source)
        XCTAssertEqual(hash.mode, 9600)
        XCTAssertTrue(hash.value.hasPrefix("$office$*2013*100000*256*16*"))
        XCTAssertEqual(hash.value.split(separator: "*").count, 8)
        let after = try FileManager.default.contentsOfDirectory(
            at: source.deletingLastPathComponent(), includingPropertiesForKeys: nil)
        XCTAssertEqual(Set(before), Set(after))
    }

    func testPlainDOCXIsRejected() {
        XCTAssertThrowsError(try OfficeHash.extract(fixture("plain.docx")))
    }

    func testEncryptedDOCExtractsRC4Hash() throws {
        let hash = try OfficeHash.extract(fixture("rc4cryptoapi_password.doc"))
        XCTAssertEqual(hash.mode, 9800)
        XCTAssertTrue(hash.value.hasPrefix("$oldoffice$4*389eb85ba016979b45872262bd473d33*"))
    }

    func testOffice2007StandardPassword() throws {
        let input = fixture("ecma376standard_password.docx")
        let hash = try OfficeHash.extract(input)
        XCTAssertEqual(hash.mode, 9400)
        XCTAssertTrue(hash.value.hasPrefix("$office$*2007*"))
        let store = KnownPasswords(service: "at.mat.iForgotMyPassword.test.\(UUID().uuidString)")
        defer { store.clear() }
        try store.add("Password1234_")
        let result = try PasswordSearch(knownPasswords: store)
            .search(input, minutes: 1, download: false) { _ in }
        guard case .found(let password) = result else {
            return XCTFail("Office-2007-Passwort wurde nicht gefunden")
        }
        XCTAssertEqual(password, "Password1234_")
    }

    func testKnownPasswordOptInAndSearch() throws {
        let store = KnownPasswords(service: "at.mat.iForgotMyPassword.test.\(UUID().uuidString)")
        defer { store.clear() }
        XCTAssertTrue(store.all().isEmpty, "Ohne Zustimmung wird nichts gespeichert")
        try store.add("Geheim123!")
        XCTAssertEqual(store.all(), ["Geheim123!"])
        let search = PasswordSearch(knownPasswords: store)
        let result = try search.search(fixture("encrypted.docx"), minutes: 1, download: false) { _ in }
        guard case .found(let password) = result else {
            return XCTFail("Das bekannte Passwort wurde nicht gefunden")
        }
        XCTAssertEqual(password, "Geheim123!")
    }

    func testKnownPasswordFindsEncryptedDOC() throws {
        let store = KnownPasswords(service: "at.mat.iForgotMyPassword.test.\(UUID().uuidString)")
        defer { store.clear() }
        try store.add("Password1234_")
        let result = try PasswordSearch(knownPasswords: store)
            .search(fixture("rc4cryptoapi_password.doc"), minutes: 1, download: false) { _ in }
        guard case .found(let password) = result else {
            return XCTFail("Das .doc-Passwort wurde nicht gefunden")
        }
        XCTAssertEqual(password, "Password1234_")
    }

    func testSearchFindsPasswordWithoutCreatingDecryptedDocument() throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let input = temporary.appendingPathComponent("Geheim123.docx")
        try FileManager.default.copyItem(at: fixture("encrypted.docx"), to: input)
        let store = KnownPasswords(service: "at.mat.iForgotMyPassword.test.\(UUID().uuidString)")
        defer { store.clear() }
        let result = try PasswordSearch(knownPasswords: store)
            .search(input, minutes: 1, download: false) { _ in }
        guard case .found(let password) = result else {
            return XCTFail("Das Passwort wurde nicht gefunden")
        }
        XCTAssertEqual(password, "Geheim123!")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: temporary.path), ["Geheim123.docx"])
        XCTAssertTrue(store.all().isEmpty, "Ein Fund wird ohne Zustimmung nicht gespeichert")
        let id = try SearchFiles.fileID(input)
        let files = try FileManager.default.contentsOfDirectory(atPath: SearchFiles.privateDirectory().path)
        XCTAssertFalse(files.contains { $0.hasPrefix(id) && $0.hasSuffix(".result") },
                       "Passwörter dürfen nicht in Ergebnisdateien landen")
    }
}
