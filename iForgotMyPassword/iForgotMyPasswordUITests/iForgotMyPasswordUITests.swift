import XCTest

final class iForgotMyPasswordUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    @MainActor
    func testInitialControls() throws {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.buttons["chooseFile"].exists)
        XCTAssertTrue(app.buttons["startSearch"].exists)
        XCTAssertFalse(app.buttons["startSearch"].isEnabled)
        XCTAssertTrue(app.steppers["searchDuration"].exists)
    }
}
