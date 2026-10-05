# Repository guidance

## Platform boundaries

- Read `docs/decisions/ADR-0001-ios-client.md` before changing or adding iOS code.
- Keep iOS implementation under `anet-ios/` and reuse `anet-client-core` and
  `anet-common` wherever their interfaces support the platform.
- Preserve `anet-mobile/` (Android) and `anet-server/` (Linux server) while
  implementing iOS. Do not move platform-specific code into those modules.
- Keep the ASTP protocol and cryptography in the existing shared crates; do not
  create an iOS-specific protocol or crypto implementation.

## Secrets and deployment

- Commit example configuration with placeholders only. Keep live `.env` files,
  private keys, client profiles, database dumps, and bot tokens out of Git.
- Keep host-specific deployment settings in `ops/` documentation and templates;
  never copy production credentials into source or release artifacts.

## Persistent decisions

- Record architecture changes under `docs/decisions/` and update the existing
  decision when its constraints change.
- Preserve additive database migrations and register each new migration in the
  appropriate migrator.
