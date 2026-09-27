import Foundation
import Darwin
import NetworkExtension

private let anetEventCallback: AnetIosEventCallback = { context, code, payload in
    guard let context else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
    let message = payload.map { String(cString: $0) } ?? ""
    provider.receiveRustEvent(code: code, payload: message)
}

private let anetPacketCallback: AnetIosPacketCallback = { context, packet, length in
    guard let context, let packet, length > 0 else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
    let data = Data(bytes: packet, count: length)
    provider.writePacket(data)
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let callbackQueue = DispatchQueue(label: "org.anet.vpn.packet-tunnel")
    private var client: OpaquePointer?
    private var startCompletion: ((Error?) -> Void)?
    private var stopping = false

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard
            let providerProtocol = protocolConfiguration as? NETunnelProviderProtocol,
            let profile = providerProtocol.providerConfiguration?["client.toml"] as? String,
            !profile.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            completionHandler(TunnelError.invalidProfile)
            return
        }

        startCompletion = completionHandler
        stopping = false
        let callbacks = AnetIosCallbacks(
            context: Unmanaged.passUnretained(self).toOpaque(),
            on_event: anetEventCallback,
            on_packet: anetPacketCallback
        )
        let profileBytes = Array(profile.utf8)
        let created = profileBytes.withUnsafeBufferPointer { buffer in
            anet_ios_client_new(buffer.baseAddress, buffer.count, callbacks)
        }
        guard let created else {
            completionHandler(TunnelError.rust(String(cString: anet_ios_last_error_message())))
            return
        }
        client = created

        guard anet_ios_client_start(created) == 0 else {
            let error = TunnelError.rust(String(cString: anet_ios_last_error_message()))
            releaseClient()
            finishStart(error)
            return
        }
        readPackets()
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stopping = true
        releaseClient()
        setTunnelNetworkSettings(nil) { _ in completionHandler() }
    }

    fileprivate func receiveRustEvent(code: Int32, payload: String) {
        callbackQueue.async { [weak self] in
            guard let self else { return }
            switch code {
            case 1000:
                self.applyNetworkSettings(payload)
            case 2:
                self.finishStart(nil)
            case 6:
                let error = TunnelError.rust(payload.isEmpty ? "ANet connection failed" : payload)
                if self.startCompletion != nil {
                    self.finishStart(error)
                } else {
                    self.cancelTunnelWithError(error)
                }
            default:
                break
            }
        }
    }

    fileprivate func writePacket(_ packet: Data) {
        callbackQueue.async { [weak self] in
            guard let self, !self.stopping, let firstByte = packet.first else { return }
            let ipVersion = firstByte >> 4
            let family = NSNumber(value: ipVersion == 6 ? AF_INET6 : AF_INET)
            self.packetFlow.writePackets([packet], withProtocols: [family])
        }
    }

    private func readPackets() {
        guard !stopping, let client else { return }
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, !self.stopping else { return }
            for packet in packets {
                packet.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    guard let baseAddress = bytes.bindMemory(to: UInt8.self).baseAddress else { return }
                    let result = anet_ios_client_send_packet(client, baseAddress, bytes.count)
                    if result == 1 {
                        NSLog("ANet packet input queue is full; one packet was dropped")
                    }
                }
            }
            self.readPackets()
        }
    }

    private func applyNetworkSettings(_ payload: String) {
        guard let data = payload.data(using: .utf8) else {
            finishStart(TunnelError.invalidNetworkSettings)
            return
        }
        guard let request = try? JSONDecoder().decode(TunnelSettingsRequest.self, from: data) else {
            if let requestID = Self.requestID(in: data) {
                completeSettings(requestID: requestID, succeeded: false)
            }
            finishStart(TunnelError.invalidNetworkSettings)
            return
        }
        guard client != nil else {
            completeSettings(requestID: request.requestId, succeeded: false)
            finishStart(TunnelError.invalidNetworkSettings)
            return
        }

        if request.reset {
            setTunnelNetworkSettings(nil) { [weak self] error in
                self?.completeSettings(requestID: request.requestId, succeeded: error == nil)
            }
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: request.remoteAddress)
        let ipv4 = NEIPv4Settings(addresses: [request.address], subnetMasks: [request.netmask])
        ipv4.includedRoutes = request.includedRoutes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: Self.mask(for: $0.prefix))
        }
        ipv4.excludedRoutes = request.excludedRoutes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: Self.mask(for: $0.prefix))
        }
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: request.mtu)
        if !request.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: request.dnsServers)
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            self.completeSettings(requestID: request.requestId, succeeded: error == nil)
            if let error, self.startCompletion != nil {
                self.finishStart(error)
            }
        }
    }

    private func completeSettings(requestID: UInt64, succeeded: Bool) {
        guard let client else { return }
        _ = anet_ios_client_complete_network_settings(client, requestID, succeeded)
    }

    private func finishStart(_ error: Error?) {
        guard let completion = startCompletion else { return }
        startCompletion = nil
        completion(error)
    }

    private func releaseClient() {
        guard let client else { return }
        _ = anet_ios_client_stop(client)
        anet_ios_client_free(client)
        self.client = nil
    }

    private static func mask(for prefix: UInt8) -> String {
        guard prefix > 0 else { return "0.0.0.0" }
        let mask = UInt32.max << (32 - Int(min(prefix, 32)))
        return "\((mask >> 24) & 255).\((mask >> 16) & 255).\((mask >> 8) & 255).\(mask & 255)"
    }

    private static func requestID(in data: Data) -> UInt64? {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let number = object["requestId"] as? NSNumber
        else { return nil }
        return number.uint64Value
    }
}

private struct TunnelSettingsRequest: Decodable {
    struct Route: Decodable {
        let address: String
        let prefix: UInt8
    }

    let requestId: UInt64
    let reset: Bool
    let remoteAddress: String
    let address: String
    let netmask: String
    let mtu: UInt16
    let dnsServers: [String]
    let includedRoutes: [Route]
    let excludedRoutes: [Route]
}

private enum TunnelError: LocalizedError {
    case invalidProfile
    case invalidNetworkSettings
    case rust(String)

    var errorDescription: String? {
        switch self {
        case .invalidProfile: return "Не удалось прочитать профиль ANet из настроек VPN."
        case .invalidNetworkSettings: return "ANet передал некорректные сетевые параметры."
        case .rust(let message): return message
        }
    }
}
