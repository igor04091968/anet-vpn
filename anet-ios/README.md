# ANet for iOS

The iOS client is a separate Swift application and Network Extension backed by
the existing Rust `anet-client-core` and `anet-common` crates. Android and Linux
server targets stay independent.

## Build prerequisites

- macOS with Xcode and the iOS SDK
- Rust installed for the same macOS account that runs Xcode
- Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and
  `x86_64-apple-ios` when building the matching simulator architecture

Open `ANetVPN/ANetVPN.xcodeproj`, select the `ANetVPN` scheme, and build for an
iOS Simulator. The extension build phase compiles `anet-ios-ffi` for the active
device or simulator target, then links the static library into Packet Tunnel.

For a local simulator build from Terminal:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
xcodebuild -project ANetVPN/ANetVPN.xcodeproj \
  -scheme ANetVPN -sdk iphonesimulator \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

## Signing and App Store preparation

The bundle identifiers currently use `org.anet.vpn.ios` as a placeholder. Set
the app and extension identifiers to identifiers registered to the publishing
team. Enable the Network Extensions capability with `packet-tunnel-provider` on
both targets and use a provisioning profile that contains that entitlement.

Apple's [App Review guideline 5.4](https://developer.apple.com/app-store/review/guidelines/)
says VPN apps must use the VPN management APIs and can only be offered by
developers enrolled as an organization. Apple's [Packet Tunnel documentation](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
requires the Network Extensions entitlement for this provider. The app also
needs a user-facing explanation of data collection and use, plus a matching
privacy policy, before App Store submission. This scaffold does not yet include
those publication materials.

## Current implementation boundary

- The app accepts a client TOML profile and manages a system VPN profile.
- The Packet Tunnel extension transfers IPv4 packets between
  `NEPacketTunnelFlow` and the Rust client.
- Rust requests Network Extension address, route, and DNS settings after ANet
  authentication; Swift applies them and returns success or failure through FFI.
- `anet-ios-ffi` owns a Tokio runtime, event bridge, packet channels, and the
  adapters required by `anet-client-core`.
- iOS does not use shell commands to alter device routes or DNS. The initial
  adapter supports IPv4; IPv6 requires a separate implementation and validation.
- The client profile includes a private key. Treat it as secret and do not log,
  export, or commit it.

The current development environment is Linux, so Xcode signing, simulator build,
device installation, and App Store validation must run on a Mac with Xcode.
