# Decibel Worker for Flare

This repository contains the independently deployable companion Worker for the Flare Kotlin mobile application. It keeps Decibel node and Gas Station credentials out of the client. It is a policy boundary, not a general proxy.

The Worker and mobile client are versioned separately. A Flare release should record the exact Worker deployment and commit it was tested against.

## Routes

- `POST /v1/session/anonymous`
- `POST /v1/auth/challenge`
- `POST /v1/auth/session`
- allowlisted `GET /decibel/api/v1/*`
- one-to-one `/decibel/ws` bridges with validated topics
- allowlisted `/aptos/v1/*` reads, views, simulation, and transaction submission
- `POST /gas/sponsor/owner`
- `POST /gas/sponsor/trading`
- `GET /gas/sponsor/status/:fingerprint`

Gas sponsorship accepts only verified Kaptos BCS transactions for configured Decibel entry functions. It binds sender, chain, package, subaccount, role, and Aptos-USDC metadata before attaching the upstream key.

Successful sponsorships are correlated by Kaptos' domain-separated request fingerprint for seven days. The fixed status route lets an interrupted client recover the on-chain transaction hash and continue normal Kaptos reconciliation without resubmitting the transaction.

## Local development

```sh
npm ci
cp .dev.vars.example .dev.vars
npm run check
npm run dev
```

`.dev.vars` must define `DECIBEL_NODE_API_KEY`, `GAS_STATION_API_KEY`, and a `SESSION_SIGNING_KEY` with at least 32 random bytes. Never commit `.dev.vars`.

For local development, pipe each value into the helper so it is never placed in shell history:

```shell
pbpaste | npm run secret:local -- DECIBEL_NODE_API_KEY
openssl rand -base64 48 | npm run secret:local -- SESSION_SIGNING_KEY
```

### Wrangler WebSocket diagnostic

An abrupt mobile-process termination can make the local workerd runtime log
`Uncaught Error: Network connection lost` after the downstream WebSocket disappears.
The bridge opts into `allowHalfOpen`, validates close codes, and coordinates both
close handshakes as required by the current [Workers WebSocket API](https://developers.cloudflare.com/workers/runtime-apis/websockets/).
The remaining local diagnostic matches the open
[workerd WebSocketPair disconnect issue](https://github.com/cloudflare/workerd/issues/5290).
It does not appear during a normal close and must not be treated as evidence that
the client failed to reconnect or backfill. Verify abrupt-disconnect behavior once
against a deployed testnet Worker before a release because the local runtime cannot
currently provide a clean signal for this case.

## Deployment

Review every non-secret variable in `wrangler.toml` for the selected network. `NETWORK`, Decibel/Aptos origins, `DECIBEL_PACKAGE_ADDRESS`, and `USDC_METADATA_ADDRESS` must describe the same immutable deployment.

Create secrets with Wrangler:

```sh
npx wrangler secret put DECIBEL_NODE_API_KEY
npx wrangler secret put GAS_STATION_API_KEY
npx wrangler secret put SESSION_SIGNING_KEY
npm run deploy
```

Use separate Worker deployments and secrets for testnet and mainnet. Do not turn a testnet deployment into mainnet by changing only one URL.

The v1 WebSocket bridge deliberately maintains one outgoing connection per mobile connection. Durable Object WebSocket hibernation does not apply to outgoing sockets, so reconnect and REST backfill remain client responsibilities.
