# Identity and policy architecture

The engine exports country-neutral TypeScript authorization primitives. An authenticated adapter supplies a trusted Context with actor, tenant, project, purpose and current time. Role authorization rejects cross-scope access. Human identities are required for administration and public release authority.

Capabilities are HMAC-SHA256 signed and bind actor, tenant, project, purpose, resource IDs, policy revision, actor revocation epoch and a maximum one-hour validity period. Consumers must obtain current epochs, policies and revoked IDs from trusted storage at the action gateway. A valid signature alone is insufficient authority. Keep signing keys in deployment key custody.

The initial package is a library; it does not provide identity federation, a database, credential issuance UI or a live service. Those work units remain planned. Shared contracts are exported at ./contracts and will be consumed through pinned engine packages. Runtime IDs are bounded opaque strings and references use immutable positive integer revisions.

Tests use only fictional scopes and temporary signing keys. No real deployment identity or research is included.
