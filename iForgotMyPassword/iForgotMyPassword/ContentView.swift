import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

private final class WeakModelBox: @unchecked Sendable {
    weak var value: AppModel?
    init(_ value: AppModel) { self.value = value }
}

@MainActor
final class AppModel: ObservableObject {
    enum Phase {
        case ready, running, paused, exhausted, found, failed
    }

    @Published var file: URL?
    @Published var minutes = 60
    @Published var phase: Phase = .ready
    @Published var status = "Wähle eine verschlüsselte Word-Datei."
    @Published var password: String?
    @Published var showDownloadQuestion = false
    @Published var showKnownQuestion = false
    @Published var knownCount = KnownPasswords().all().count

    private var engine: PasswordSearch?
    private var downloadChoice: Bool?

    deinit {
        engine?.cancel()
    }

    func select(_ url: URL) {
        guard phase != .running else { return }
        guard ["doc", "docx"].contains(url.pathExtension.lowercased()) else {
            phase = .failed
            status = "Bitte eine .doc- oder .docx-Datei auswählen."
            return
        }
        file = url
        downloadChoice = nil
        phase = .ready
        password = nil
        status = "Bereit für die Passwortsuche."
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "doc")!, UTType(filenameExtension: "docx")!]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { select(url) }
    }

    func start() {
        guard file != nil, phase != .running else { return }
        if downloadChoice == nil && Wordlists.cached().count < Wordlists.sources.count {
            showDownloadQuestion = true
        } else {
            search(download: downloadChoice ?? false)
        }
    }

    func search(download: Bool) {
        guard let file, phase != .running else { return }
        downloadChoice = download
        password = nil
        phase = .running
        status = "Lese Passwort-Prüfdaten …"
        let engine = PasswordSearch()
        self.engine = engine
        let minutes = minutes
        let box = WeakModelBox(self)
        Task.detached {
            do {
                let result = try engine.search(file, minutes: minutes, download: download) { message in
                    Task { @MainActor in
                        if box.value?.phase == .running { box.value?.status = message }
                    }
                }
                await MainActor.run {
                    guard let self = box.value else { return }
                    self.engine = nil
                    switch result {
                    case .found(let password):
                        self.password = password
                        self.status = "Passwort gefunden."
                        self.phase = .found
                        self.showKnownQuestion = true
                    case .paused:
                        self.phase = .paused
                        self.status = "Suche angehalten. Du kannst sie fortsetzen."
                    case .exhausted:
                        self.phase = .exhausted
                        self.status = "Mit diesen Suchverfahren wurde kein Passwort gefunden."
                    }
                }
            } catch {
                await MainActor.run {
                    guard let self = box.value else { return }
                    self.engine = nil
                    self.phase = .failed
                    self.status = error.localizedDescription
                }
            }
        }
    }

    func pause() {
        engine?.cancel()
        status = "Suche wird angehalten …"
    }

    func addKnownPassword() {
        guard let password else { return }
        do {
            try KnownPasswords().add(password)
            knownCount = KnownPasswords().all().count
            status = "Passwort gefunden und zu „Known Passwords“ hinzugefügt."
        } catch {
            status = error.localizedDescription
            phase = .failed
        }
    }
}

struct ContentView: View {
    @StateObject private var model = AppModel()
    @State private var dropTargeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(spacing: 14) {
                Image(systemName: "lock.doc")
                    .font(.system(size: 38, weight: .light))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text("iForgotMyPassword").font(.largeTitle.bold())
                    Text("Passwort für eine Word-Datei finden")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            VStack(spacing: 14) {
                Image(systemName: "doc.badge.plus")
                    .font(.system(size: 36, weight: .light))
                    .foregroundStyle(.secondary)
                Text(model.file?.lastPathComponent ?? "Word-Datei hier ablegen")
                    .font(.headline)
                    .lineLimit(1)
                Text(".doc oder .docx · Die Originaldatei bleibt unverändert")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Datei auswählen …") { model.chooseFile() }
                    .disabled(model.phase == .running)
                    .accessibilityIdentifier("chooseFile")
            }
            .frame(maxWidth: .infinity, minHeight: 180)
            .background(dropTargeted ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(
                dropTargeted ? Color.accentColor : Color.secondary.opacity(0.25),
                style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [7])))
            .onDrop(of: [UTType.fileURL.identifier], isTargeted: $dropTargeted) { providers in
                guard let provider = providers.first, model.phase != .running else { return false }
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url { Task { @MainActor in model.select(url) } }
                }
                return true
            }

            HStack {
                Text("Suchdauer")
                Spacer()
                Stepper(value: $model.minutes, in: 1...1440, step: 5) {
                    Text("\(model.minutes) Minuten")
                        .monospacedDigit()
                        .frame(minWidth: 95, alignment: .trailing)
                }
                .disabled(model.phase == .running)
                .accessibilityIdentifier("searchDuration")
            }

            HStack(spacing: 12) {
                if model.phase == .running {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: statusSymbol)
                        .foregroundStyle(model.phase == .failed ? .red : .secondary)
                }
                Text(model.status).font(.subheadline).lineLimit(2)
                Spacer()
            }
            .frame(minHeight: 38)
            .accessibilityIdentifier("searchStatus")

            if let password = model.password {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Gefundenes Passwort").font(.caption).foregroundStyle(.secondary)
                        Text(password).font(.title3.monospaced()).textSelection(.enabled)
                    }
                    Spacer()
                    Button("Kopieren") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(password, forType: .string)
                    }
                    .accessibilityIdentifier("copyPassword")
                }
                .padding(16)
                .background(Color.green.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
            }

            HStack {
                Text("Known Passwords: \(model.knownCount)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if model.phase == .running {
                    Button("Anhalten") { model.pause() }
                        .accessibilityIdentifier("pauseSearch")
                } else {
                    Button(model.phase == .paused ? "Fortsetzen" : "Suche starten") { model.start() }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.file == nil)
                        .accessibilityIdentifier("startSearch")
                }
            }
        }
        .padding(28)
        .frame(minWidth: 590, minHeight: 500)
        .alert("Wortlisten herunterladen?", isPresented: $model.showDownloadQuestion) {
            Button("Ohne Download suchen", role: .cancel) { model.search(download: false) }
            Button("Listen herunterladen") { model.search(download: true) }
        } message: {
            Text("Die App lädt Passwortlisten von SecLists und Kali Wordlists. Der Download kann über 50 MB groß sein; die entpackten Listen benötigen deutlich mehr Speicherplatz.")
        }
        .alert("Zu „Known Passwords“ hinzufügen?", isPresented: $model.showKnownQuestion) {
            Button("Nein", role: .cancel) {}
            Button("Ja, speichern") { model.addKnownPassword() }
        } message: {
            Text("Das gefundene Passwort wird nur mit deiner Zustimmung dauerhaft im macOS-Schlüsselbund gespeichert und bei späteren Suchen zuerst geprüft.")
        }
    }

    private var statusSymbol: String {
        switch model.phase {
        case .ready: "doc.text"
        case .running: "hourglass"
        case .paused: "pause.circle"
        case .exhausted: "questionmark.circle"
        case .found: "checkmark.circle.fill"
        case .failed: "exclamationmark.triangle"
        }
    }
}

#Preview {
    ContentView()
}
