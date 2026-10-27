# Identity and policy architecture

The engine exports country-neutral TypeScript authorization primitives. An authenticated adapter supplies a trusted Context with actor, tenant, project, purpose and current time. Role authorization rejects cross-scope access. Human identities are required for administration and public release authority.

Capabilities are HMAC-SHA256 signed and bind actor, tenant, project, purpose, resource IDs, policy revision, actor revocation epoch and a maximum one-hour validity period. Consumers must obtain current epochs, policies and revoked IDs from trusted storage at the action gateway. A valid signature alone is insufficient authority. Keep signing keys in deployment key custody.

The initial package is a library; it does not provide identity federation, credential issuance UI or a live service. Opt-in durable modules below use an Identity-owned operational database; hosting and federation remain pending. Shared contracts are exported at ./contracts and will be consumed through pinned engine packages. Runtime IDs are bounded opaque strings and references use immutable positive integer revisions.

Tests use only fictional scopes and temporary signing keys. No real deployment identity or research is included.

## Managed intake service adapter

`verifyIntakeService` validates one deployment-configured intake connection using its pinned managed credential and authenticated capability contract. The source returns no organization/client identity; an arbitrary upstream token therefore cannot establish a local tenant. The adapter refuses a credential whose fingerprint differs from the trusted mapping and never maps upstream scope strings into local roles. It returns only a local service identity with explicitly configured non-owner roles. Responses are bounded, redirects denied, engine versions pinned and required scopes checked. Tokens remain in credential/transport callbacks and are excluded from returned identity data.

This is managed service verification. End-user login/federation and host provisioning remain separate work; the opt-in durable policy modules are described below. The host must trust mapping/key custody and independently authenticate incoming users before allowing a connection to be used.

Managed verification now snapshots configuration before any callback and applies one cancellable 10-second default deadline (configurable 10–30000ms) across credential lookup, transport and body reads. The credential callback receives the same AbortSignal as transport. JSON UTF8, 64KiB and 4096-chunk limits apply; late responses are discarded and callback diagnostics sanitized. This is a local callback/Fetch boundary, not a qualified deployed network or authentication service. Ten new synthetic callback/native-Fetch groups exercise mapping mutation, credential/body stalls, abort, zero-byte chunk floods, bounded malformed input, copied chunks, sanitized errors and monotonic expiry. Final-head CI is recorded in the PR.

The default transport remains host-configured HTTPS Fetch with manual redirects. This change does not add an SSRF-resistant DNS/egress gateway or independently prove the remote organization: trusted deployment mapping and credential custody remain mandatory. Timeouts/cancellation stop acceptance and subsequent stages, but cannot forcibly terminate arbitrary host callbacks or undo their side effects. Monotonic deadline checks reject synchronous overruns at stage boundaries; they do not preempt blocked JavaScript. A host must reverify using current mapping after revocation; an earlier returned service identity is a historical snapshot, not current authorization.

## Durable revocation administration

[Revocations](REVOCATIONS.md) adds an opt-in Identity-owned operational database for policy/actor epoch changes, exact capability revocation and transactional audit/outbox. Verification reads current state and a post-load live clock under the same project lock. Host authentication, fixed administrator configuration and signing-key custody remain external trust boundaries. This is partial IAP-005 work, not federation, dynamic membership, a deployed gateway or distributed action fencing.

## Independent database sessions

POSTGRES_TESTS.md defines disposable PostgreSQL17 CI for revocation contenders, observed lock waits, current expiry/revocation, lost acknowledgements and restricted roles. This is distinct from embedded tests and production identity/key/deployment qualification. Actual final-head CI is required; no local network execution is claimed.

## Persistent project membership

[Membership](MEMBERSHIP.md) supplies bounded dynamic roles, disable/re-enable, current stored human-owner administration before cached acknowledgements and last-owner/permanent-kind protection in the Identity-owned DB. Own-principal action resolution discards incoming roles, reloads stored policy under the project lock and returns an explicit policy revision/member epoch snapshot. This is additional partial IAP-005 work, not authentication, a deployed gateway, automatic capability epoch synchronization, compartment policy or distributed action fencing. Fixed-list RevocationRegistry admission remains a separate interface.
