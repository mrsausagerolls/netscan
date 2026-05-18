import SwiftUI

struct ContentView: View {
    @EnvironmentObject var client: INSClient

    var body: some View {
        NavigationStack {
            List {
                if !client.connected {
                    connectionSection
                }
                if let h = client.state?.health {
                    healthSection(h)
                }
                if let alerts = client.state?.alerts, !alerts.isEmpty {
                    alertsSection(alerts)
                }
                if let devices = client.state?.devices, !devices.isEmpty {
                    devicesSection(devices)
                }
            }
            .navigationTitle("Inglorious Network Scanner")
            .listStyle(.insetGrouped)
        }
    }

    // MARK: Connection

    private var connectionSection: some View {
        Section("Connection") {
            HStack {
                Image(systemName: "wifi.exclamationmark")
                    .foregroundStyle(.orange)
                Text(client.lastError ?? "Looking for a running INS on this network…")
                    .font(.footnote)
            }
            HStack {
                TextField("Manual host (e.g. 10.0.0.4)", text: $client.manualHost)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Connect") { client.setManualHost(client.manualHost) }
            }
        }
    }

    // MARK: Health

    private func healthSection(_ h: Health) -> some View {
        Section("Network Health") {
            HStack(spacing: 16) {
                Text("\(h.score ?? 0)")
                    .font(.system(size: 44, weight: .semibold, design: .rounded))
                VStack(alignment: .leading, spacing: 4) {
                    Text((h.band ?? "—").capitalized)
                        .font(.caption.weight(.semibold))
                        .textCase(.uppercase)
                        .foregroundStyle(band: h.band)
                    Text(h.headline ?? "")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(h.reasons ?? [], id: \.label) { r in
                HStack {
                    Text("−\(r.weight ?? 0)").font(.caption.monospaced()).foregroundStyle(.red)
                    Text(r.label ?? "").font(.caption)
                }
            }
        }
    }

    // MARK: Alerts

    private func alertsSection(_ alerts: [Alert]) -> some View {
        Section("Recent Alerts") {
            ForEach(alerts.prefix(10), id: \.id) { a in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Image(systemName: iconForSeverity(a.severity))
                            .foregroundStyle(colorForSeverity(a.severity))
                        Text(a.title ?? "Alert")
                            .font(.subheadline.weight(.semibold))
                    }
                    Text(a.message ?? "")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: Devices

    private func devicesSection(_ devices: [Device]) -> some View {
        Section("Devices on \(client.state?.ssid ?? "network")") {
            ForEach(devices, id: \.mac) { d in
                HStack {
                    Text(d.type_icon ?? "❔")
                        .font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(d.known_name ?? d.hostname ?? d.vendor ?? d.mac)
                            .font(.subheadline)
                        Text("\(d.ip ?? "—")  ·  \(d.type_label ?? "Unknown")")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    statusDot(d)
                }
            }
        }
    }

    private func statusDot(_ d: Device) -> some View {
        Circle()
            .fill(d.me == true ? Color.blue
                  : d.is_known == true ? Color.green
                  : Color.red)
            .frame(width: 10, height: 10)
    }

    private func iconForSeverity(_ sev: String?) -> String {
        switch sev {
        case "critical": return "exclamationmark.triangle.fill"
        case "warning":  return "exclamationmark.bubble.fill"
        default:         return "antenna.radiowaves.left.and.right"
        }
    }

    private func colorForSeverity(_ sev: String?) -> Color {
        switch sev {
        case "critical": return .red
        case "warning":  return .orange
        default:         return .blue
        }
    }
}

private extension Text {
    func foregroundStyle(band: String?) -> some View {
        let color: Color = {
            switch band {
            case "excellent", "good": return .green
            case "fair", "poor":      return .orange
            case "at_risk":           return .red
            default:                  return .secondary
            }
        }()
        return self.foregroundStyle(color)
    }
}

#Preview {
    ContentView().environmentObject(INSClient())
}
