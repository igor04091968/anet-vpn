import Foundation
import Combine
import NetworkExtension

final class VPNManager: ObservableObject {
    private static let extensionBundleIdentifier = "org.anet.vpn.ios.PacketTunnel"

    @Published var clientToml = ""
    @Published private(set) var status = "Не подключено"
    @Published private(set) var errorMessage: String?
    @Published private(set) var isBusy = false

    var isConnected: Bool {
        status == "Подключено"
    }

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    func reload() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    self.errorMessage = error.localizedDescription
                    return
                }
                self.manager = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
                })
                if let provider = self.manager?.protocolConfiguration as? NETunnelProviderProtocol {
                    self.clientToml = provider.providerConfiguration?["client.toml"] as? String ?? ""
                }
                self.refreshStatus()
            }
        }
    }

    func connect() {
        let profile = clientToml.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !profile.isEmpty else {
            errorMessage = "Вставьте конфигурацию ANet."
            return
        }

        isBusy = true
        errorMessage = nil
        loadOrCreateManager { [weak self] manager, error in
            guard let self else { return }
            guard let manager else {
                self.finish(error: error ?? VPNManagerError.managerUnavailable)
                return
            }

            let provider = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            provider.providerBundleIdentifier = Self.extensionBundleIdentifier
            provider.serverAddress = "ANet VPN"
            provider.providerConfiguration = ["client.toml": profile]
            manager.protocolConfiguration = provider
            manager.localizedDescription = "ANet VPN"
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if let saveError {
                    self.finish(error: saveError)
                    return
                }
                manager.loadFromPreferences { loadError in
                    if let loadError {
                        self.finish(error: loadError)
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        DispatchQueue.main.async {
                            self.manager = manager
                            self.status = "Подключение…"
                            self.isBusy = false
                        }
                    } catch {
                        self.finish(error: error)
                    }
                }
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        status = "Отключение…"
    }

    private func loadOrCreateManager(_ completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self else { return }
            if let error {
                completion(nil, error)
                return
            }
            let existing = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionBundleIdentifier
            })
            completion(existing ?? NETunnelProviderManager(), nil)
        }
    }

    private func refreshStatus() {
        guard let manager else { return }
        let value: String
        switch manager.connection.status {
        case .connected: value = "Подключено"
        case .connecting, .reasserting: value = "Подключение…"
        case .disconnecting: value = "Отключение…"
        case .disconnected, .invalid: value = "Не подключено"
        @unknown default: value = "Состояние неизвестно"
        }
        status = value
    }

    private func finish(error: Error?) {
        DispatchQueue.main.async {
            self.isBusy = false
            if let error {
                self.errorMessage = error.localizedDescription
                self.status = "Не подключено"
            }
        }
    }
}

private enum VPNManagerError: LocalizedError {
    case managerUnavailable

    var errorDescription: String? {
        "Не удалось создать конфигурацию VPN."
    }
}
