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
        if let url = makeBaseURL(from: manualHost) {
            connect(to: url)
        }
    }

    /// Build the dashboard base URL from a user-entered host, tolerating a
    /// pasted scheme ("http://10.0.0.4"), an explicit ":port" ("10.0.0.4:8765"),
    /// a trailing path, and surrounding whitespace — all of which made the old
    /// `URL(string: "http://\(host):8765")` interpolation produce nil or a
    /// wrong URL. Defaults to port 8765. Sets lastError and returns nil on
    /// invalid input so the user gets feedback instead of a silent no-op.
    private func makeBaseURL(from raw: String) -> URL? {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.isEmpty { return nil }
        if let r = host.range(of: "://") { host = String(host[r.upperBound...]) }
        if let slash = host.firstIndex(of: "/") { host = String(host[..<slash]) }
        var port = 8765
        if let colon = host.lastIndex(of: ":") {
            let portStr = String(host[host.index(after: colon)...])
            if let p = Int(portStr), p > 0, p < 65536 {
                port = p
                host = String(host[..<colon])
            }
        }
        guard !host.isEmpty else { lastError = "Invalid host"; return nil }
        var comps = URLComponents()
        comps.scheme = "http"
        comps.host = host
        comps.port = port
        guard let url = comps.url else { lastError = "Invalid host"; return nil }
        return url
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
                    // Resolve to a host:port via a transient connection. The
                    // browser callback runs on the main queue, but hop onto the
                    // MainActor explicitly so this compiles under Swift 6 strict
                    // concurrency (resolve() is @MainActor-isolated).
                    Task { @MainActor in self.resolve(service: name) }
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
            let (data, resp) = try await URLSession.shared.data(for: req)
            // Validate the HTTP status before decoding. The dashboard returns
            // 200 + the SPA shell (HTML) for unknown paths and JSON error
            // bodies for 4xx/5xx; without this check a misconfigured host
            // surfaces as an opaque JSON "dataCorrupted" error.
            if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                throw URLError(.badServerResponse)
            }
            let decoded = try JSONDecoder().decode(INSState.self, from: data)
            self.state = decoded
            self.connected = true
            self.lastError = nil
        } catch {
            self.lastError = "Couldn't load \(stateURL.host ?? "host"): \(error.localizedDescription)"
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
                    // Minimal SSE parser. Each event arrives as an "event:"
                    // line followed by a "data:" line; key only on "data:" so
                    // we refresh once per event, not twice. We don't parse the
                    // payload — the UI re-renders from /api/state anyway.
                    if line.hasPrefix("data:") {
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
