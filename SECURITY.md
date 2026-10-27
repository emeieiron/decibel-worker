# Security policy

This service is a credential and transaction-authorization boundary. Report vulnerabilities privately to the repository maintainers rather than opening a public issue.

Include the affected commit, route, prerequisites, and a minimal reproduction. This service is mainnet-only, so prefer a reproduction that reads rather than one that signs or spends; never attach a reproduction that moves real funds. Never include live node keys, Gas Station keys, session signing keys, wallet private keys, mnemonics, session tokens, or funded-account signatures.

Production deployment requires mainnet-scoped secrets of its own, passing authentication and sponsorship-policy tests, and an independently reviewed route allowlist. Because the Worker sponsors transactions against real funds, treat the Gas Station function allowlist as part of that review.
