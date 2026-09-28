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
}
