import SwiftUI

struct ContentView: View {
    @StateObject private var vpn = VPNManager()

    var body: some View {
        NavigationView {
            Form {
                Section("Профиль ANet") {
                    TextEditor(text: $vpn.clientToml)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 260)
                        .accessibilityLabel("Конфигурация клиента ANet")

                    Text("Профиль содержит приватный ключ. Передавайте его только доверенному устройству.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Подключение") {
                    HStack {
                        Text("Состояние")
                        Spacer()
                        Text(vpn.status).foregroundStyle(.secondary)
                    }

                    Button("Сохранить профиль и подключиться") {
                        vpn.connect()
                    }
                    .disabled(vpn.clientToml.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || vpn.isBusy)

                    Button("Отключить", role: .destructive) {
                        vpn.disconnect()
                    }
                    .disabled(!vpn.isConnected)
                }

                if let error = vpn.errorMessage {
                    Section("Ошибка") {
                        Text(error).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("ANet VPN")
            .task { vpn.reload() }
        }
    }
}
