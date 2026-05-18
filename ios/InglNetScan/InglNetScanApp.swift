import SwiftUI

@main
struct InglNetScanApp: App {
    @StateObject private var client = INSClient()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(client)
                .task { await client.start() }
        }
    }
}
