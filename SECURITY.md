# Security policy

This service is a credential and transaction-authorization boundary. Report vulnerabilities privately to the repository maintainers rather than opening a public issue.

Include the affected commit, route, network, prerequisites, and a minimal testnet-only reproduction. Never include live node keys, Gas Station keys, session signing keys, wallet private keys, mnemonics, session tokens, or funded-account signatures.

Production deployment requires separate testnet and mainnet secrets, passing authentication and sponsorship-policy tests, and an independently reviewed route allowlist. Mainnet credentials must not be introduced merely by changing a testnet deployment's origins.
