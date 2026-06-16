import Foundation

// Mirrors the subset of /api/state we render on the phone.
//
// We don't decode the entire payload — only the fields the read-only view
// actually shows. New backend fields are silently ignored by Swift's
// Decodable + ignored-keys default behavior.

struct INSState: Decodable {
    let ssid: String?
    let network: String?
    let count: Int?
    let last_scan: String?
    let devices: [Device]?
    let alerts: [Alert]?
    let health: Health?
}

struct Device: Decodable, Identifiable, Hashable {
    var id: String { mac }
    let mac: String
    let ip: String?
    let hostname: String?
    let vendor: String?
    let known_name: String?
    let type_label: String?
    let type_icon: String?
    let device_type: String?
    let is_known: Bool?
    let me: Bool?
}

struct Alert: Decodable, Identifiable, Hashable {
    var id: Int { idFallback ?? Int(ts ?? 0) }
    let idFallback: Int?
    let ts: Double?
    let kind: String?
    let severity: String?
    let title: String?
    let message: String?
    let acknowledged: Int?

    enum CodingKeys: String, CodingKey {
        case idFallback = "id"
        case ts, kind, severity, title, message, acknowledged
    }
}

struct Health: Decodable, Hashable {
    let score: Int?
    let band: String?
    let headline: String?
    let reasons: [HealthReason]?
}

struct HealthReason: Decodable, Hashable {
    let weight: Int?
    let label: String?
}
