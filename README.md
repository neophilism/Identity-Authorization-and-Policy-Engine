# Identity, Authorization and Policy Engine

Reusable tenant/project authorization, authenticated actor mapping, purpose-scoped signed capabilities and revocation. Deployment-specific policies and research belong in downstream applications.

```sh
npm ci
npm run check
npm run build
```

Initial library capabilities: trusted actor contexts, role authorization, human authority for administrative/release operations, signed purpose/resource grants, expiry, policy revisions and revocation epochs. Identity federation, durable administration, compartment projections and live service acceptance remain planned in [registry/prs.json](registry/prs.json).

See [architecture](docs/ARCHITECTURE.md). Tests use fictional scopes and temporary keys. The Public Accountability Machine consumes this engine after its dependency contract is ready.
