# Identity and policy architecture

The engine exports country-neutral TypeScript authorization primitives. An authenticated adapter supplies a trusted Context with actor, tenant, project, purpose and current time. Role authorization rejects cross-scope access. Human identities are required for administration and public release authority.

Capabilities are HMAC-SHA256 signed and bind actor, tenant, project, purpose, resource IDs, policy revision, actor revocation epoch and a maximum one-hour validity period. Consumers must obtain current epochs, policies and revoked IDs from trusted storage at the action gateway. A valid signature alone is insufficient authority. Keep signing keys in deployment key custody.

The initial package is a library; it does not provide identity federation, a database, credential issuance UI or a live service. Those work units remain planned. Shared contracts are exported at ./contracts and will be consumed through pinned engine packages. Runtime IDs are bounded opaque strings and references use immutable positive integer revisions.

Tests use only fictional scopes and temporary signing keys. No real deployment identity or research is included.

## Managed intake service adapter

`verifyIntakeService` validates one deployment-configured intake connection using its pinned managed credential and authenticated capability contract. The source returns no organization/client identity; an arbitrary upstream token therefore cannot establish a local tenant. The adapter refuses a credential whose fingerprint differs from the trusted mapping and never maps upstream scope strings into local roles. It returns only a local service identity with explicitly configured non-owner roles. Responses are bounded, redirects denied, engine versions pinned and required scopes checked. Tokens remain in credential/transport callbacks and are excluded from returned identity data.

This is managed service verification. End-user login/federation, member provisioning and durable administrative policy remain separate work. The host must trust mapping/key custody and independently authenticate incoming users before allowing a connection to be used.
