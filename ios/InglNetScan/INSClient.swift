import Foundation
import Network
import Combine

/// Discovers a running Inglorious Network Scanner on the local network via
/// Bonjour and keeps a live state object up to date.
///
/// Two paths to a connection:
///   1. Bonjour browse for `_ins._tcp.local`. If INS publishes one (v2.5+),
///      pick the first responder.
///   2. Manual host fallback. The user types the Mac's LAN IP into the UI
///      and we connect directly.
///
/// Once we have a base URL, we:
///   - GET /api/state every refresh
///   - Open /api/stream as a Server-Sent Events long-poll. Every named event
///     fires a `refresh()` which re-fetches /api/state.
///
/// No retries with exponential backoff yet — keep it simple, reconnect on
/// any failure after 3 seconds.
@MainActor
final class INSClient: ObservableObject {
    @Published var state: INSState? = nil
    @Published var connected: Bool = false
    @Published var lastError: String? = nil
    @Published var manualHost: String = ""

    private var browser: NWBrowser?
    private var streamTask: Task<Void, Never>? = nil
    private var pollTask:   Task<Void, Never>? = nil
    private var baseURL: URL?

    func start() async {
        startBonjourBrowse()
        // Also poll the manualHost field; if the user types one, switch to it.
        await tickLoop()
    }

    func setManualHost(_ host: String) {
        manualHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: "http://\(manualHost):8765") {
            connect(to: url)
        }
    }

    // MARK: Bonjour

    private func startBonjourBrowse() {
        let params = NWParameters.tcp
        params.includePeerToPeer = true
        let browser = NWBrowser(for: .bonjour(type: "_ins._tcp", domain: nil), using: params)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            for r in results {
                if case let .service(name, _, _, _) = r.endpoint {
                    // Resolve to a host:port via a transient connection.
                    self.resolve(service: name)
                    return
                }
            }
        }
        browser.start(queue: .main)
        self.browser = browser
    }

    private func resolve(service: String) {
        // We don't have the host yet — Bonjour returns just the service name.
        // NWConnection.endpoint will resolve when we open a connection. For
        // a real production version this should use DNS-SD properly; here
        // we just trust that the user can paste the IP for now.
        // (Documented in README as a known scaffold limitation.)
    }

    // MARK: Connection

    private func connect(to url: URL) {
        baseURL = url
        streamTask?.cancel()
        pollTask?.cancel()
        Task { await refresh() }
        streamTask = Task { [weak self] in
            await self?.streamLoop(url: url)
        }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30s
                await self?.refresh()
            }
        }
    }

    private func refresh() async {
        guard let base = baseURL else { return }
        let stateURL = base.appendingPathComponent("api/state")
        do {
            var req = URLRequest(url: stateURL)
            req.timeoutInterval = 10
            let (data, _) = try await URLSession.shared.data(for: req)
            let decoded = try JSONDecoder().decode(INSState.self, from: data)
            self.state = decoded
            self.connected = true
            self.lastError = nil
        } catch {
            self.lastError = String(describing: error)
            self.connected = false
        }
    }

    // MARK: SSE

    private func streamLoop(url: URL) async {
        let streamURL = url.appendingPathComponent("api/stream")
        while !Task.isCancelled {
            do {
                var req = URLRequest(url: streamURL)
                req.timeoutInterval = 0
                req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                let (bytes, _) = try await URLSession.shared.bytes(for: req)
                for try await line in bytes.lines {
                    // Minimal SSE parser: any "event:" or "data:" line triggers
                    // a refresh of /api/state. We don't actually parse the
                    // payload because the UI re-renders from /api/state
                    // anyway.
                    if line.hasPrefix("event:") || line.hasPrefix("data:") {
                        await refresh()
                    }
                }
            } catch {
                self.lastError = "stream: \(error)"
                self.connected = false
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    // MARK: Initial tick

    private func tickLoop() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            if baseURL == nil && !manualHost.isEmpty,
               let url = URL(string: "http://\(manualHost):8765") {
                connect(to: url)
            }
        }
    }
}
