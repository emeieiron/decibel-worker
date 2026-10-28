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
- `POST /swap/quote`
- `POST /gas/sponsor/owner`
- `POST /gas/sponsor/trading`
- `GET /gas/sponsor/status/:fingerprint`
- `GET /gas/sponsor/swap-availability` (owner session; read-only deployment policy)

Gas sponsorship accepts only verified Kaptos BCS transactions for configured Decibel entry functions or quote-authorized Panora swaps. It binds sender, chain, package, subaccount, role, and Aptos-USDC metadata before attaching the upstream key. The Worker then converts Kaptos’ signed `RawTransactionWithData` envelope to the `SimpleTransaction` envelope required by `@aptos-labs/gas-station-client`. The signed raw transaction and authenticator remain unchanged; fingerprints continue to identify the original Kaptos request. Compatibility tests deserialize the outbound bytes with the official Aptos SDK and compare signing messages.

Successful sponsorships are correlated by Kaptos' domain-separated request fingerprint for seven days. The fixed status route lets an interrupted client recover the on-chain transaction hash and continue normal Kaptos reconciliation without resubmitting the transaction.

## Local development

```sh
npm ci
cp .dev.vars.example .dev.vars
npm run check
npm run dev
```

`.dev.vars` must define `DECIBEL_NODE_API_KEY` and a `SESSION_SIGNING_KEY` with at least 32 random bytes. Set `GAS_STATION_API_KEY` to enable sponsorship; this is a separate **Geomi Gas Station resource key**, not the node API key. Never commit `.dev.vars`.

An absent or blank Gas Station key returns HTTP 503 with `code=gas_station_not_configured` without submitting a new transaction. Previously submitted or pending fingerprints are still resolved first. An upstream 401 returns HTTP 503 with `code=gas_station_credentials_rejected` after releasing its reservation. A transaction outside the sponsorship policy (function, module, role, subaccount, asset, or argument checks) returns HTTP 403 with `code=gas_station_transaction_not_allowed` before anything is reserved or submitted. None of these invalidates the mobile wallet session. Clients may offer explicit self-pay for those three codes; a generic 503 or transport failure remains uncertain and must not trigger resubmission.

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
against the deployed Worker before a release because the local runtime cannot
currently provide a clean signal for this case.

## Deployment

This Worker is mainnet-only: it serves Decibel on Aptos mainnet and has no testnet mode. `NETWORK` is pinned to `mainnet`, `parseChallenge` rejects a challenge signed for any other network, and only chain id 1 is sponsored. Review every non-secret variable in `wrangler.toml` before deploying: the Decibel and Aptos origins, `DECIBEL_PACKAGE_ADDRESS` and `USDC_METADATA_ADDRESS` must all describe the same immutable mainnet deployment.

Create secrets with Wrangler:

```sh
npx wrangler secret put DECIBEL_NODE_API_KEY
npx wrangler secret put GAS_STATION_API_KEY
npx wrangler secret put SESSION_SIGNING_KEY
npx wrangler secret put PANORA_API_KEY
npm run deploy
```

The node key and the Gas Station resource key are per-network, so a deployment needs its own mainnet credentials; rotate `SESSION_SIGNING_KEY` whenever the deployment's scope changes, since that is what invalidates sessions already issued.

Note that `npm run dev` reads the same `[vars]`, so a local Worker proxies mainnet. Keep the mainnet Gas Station key out of `.dev.vars` unless you intend to sponsor real transactions.

The v1 WebSocket bridge deliberately maintains one outgoing connection per mobile connection. Durable Object WebSocket hibernation does not apply to outgoing sockets, so reconnect and REST backfill remain client responsibilities.

## Swap infrastructure

`POST /swap/quote` accepts an owner session and `{owner, kind, amount, slippageBps}`. Amounts are integer base-unit strings; kinds are `EXACT_INPUT` or `EXACT_OUTPUT`. Only Aptos-mainnet APT to Circle-native USDC, direct FA routes, up to 100 bps slippage and zero provider fees are supported. `SWAPS_ENABLED` is enabled in `wrangler.toml`; the `PANORA_API_KEY` secret is also required. Panora's [documented public API key](https://docs.panora.exchange/developer/swap/api) is sufficient to start; a dedicated key can replace it if capacity requires one. Keep the key in Worker configuration so it can be rotated without a mobile release.

The response includes a normalized provider response and a domain-separated signed authorization binding the wallet, payload hash and expiry. The client must independently encode and verify the payload. Sponsored submissions attach this token as `swapAuthorization` on `/gas/sponsor/owner`; the worker verifies the signature, owner, exact payload, expiry and gas bounds. Quote usage is reserved in durable storage, so one quote cannot sponsor different signed transactions. Existing sponsorship fingerprints retain submission recovery.

Sponsorship uses the existing `GAS_STATION_API_KEY`; no new Gas Station credential is required. Allow the verified Panora router in the upstream Gas Station policy to sponsor swaps. Quotes and self-paid execution do not depend on this policy: if Flare definitively cannot sponsor, the client offers execution paid with the user's APT. A timeout or uncertain submission must be reconciled before attempting self-pay, to avoid a duplicate swap. Self-paid execution remains the client's responsibility.

Quote requests use a dedicated budget of 30 requests per minute per owner, independent session and IP rate limits, an eight-second provider deadline, a 128 KiB response limit and per-isolate backoff after repeated transport failures. Executable quotes are never shared across wallets or cached. Provider transaction envelopes and signing messages are discarded. The captured public mainnet quote in the tests is never submitted.

When Panora’s best direct route uses unsupported coin types, the Worker requests a Hyperion route within the same eight-second deadline. The replacement must pass the same FA asset, recipient, input/output, fee, slippage and payload checks before any authorization is issued. The response also includes `issuedAtMs` and `expiresAtMs` so clients can derive a conservative local lifetime without assuming synchronized clocks.

### Swap fee preflight

Swap sponsorship is explicitly opt-in through `SWAP_SPONSORSHIP_ENABLED`. It is disabled in the current deployment because the live Gas Station returned HTTP 404. Enable it only after verifying the Gas Station resource and upstream Panora contract policy. The owner-only availability route never signs, reserves a quote, or submits a transaction. It reports false for a disabled or unconfigured sponsor, and after a definite upstream rejection applies a per-isolate 60-second cooldown. This is a deployment policy check: the published Geomi client exposes only sign-and-submit, without an unsigned eligibility or budget-reservation API. A positive response cannot guarantee later acceptance. Mobile clients must display the chosen fee payer and simulate the exact swap before asking for authorization. An unavailable preflight may select explicit self-pay before signing; an uncertain submitted transaction must still be reconciled before any replacement.
