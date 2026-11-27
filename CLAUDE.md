# trusted-issuers-LAB

Tester-tier lab. Where a token from another issuer is trusted: PingOne token exchange (A), PingOne Authorize (B), Privilege Federated Identity (C), PingFederate ID-JAG (D), against 14 issuer types. Content is data in `data/*.json`; the engine in `server/src` mints tokens with its own RSA keys and runs each surface's checks with real RS256 verification.

## Run and test
- `npm ci`, `npm start` (127.0.0.1:7815), `npm test` (`node --test test/*.test.js` in `server/`), `npm run doctor`, `npm run reset`.
- Docker: `docker compose up --build` (OrbStack, never Docker Desktop). Published on 127.0.0.1 only.
- Run tests on the Air (`air-test`) when this Mac is loaded; `git add` new files first.

## The rules that bite here
- **Every claim has an evidence tag and a source** (`docs`, `measured`, `deck`, `lab-reading`, `unverified`; sources in `data/sources.json`). `supported` needs docs or measured. `validateData()` in `server/src/data.js` enforces it, and the doctor, `/api/health` and the tests all run it. Add the source first, then the claim.
- **Never show lab wording as a product's text.** A refusal's `messageSource` is `docs`, `measured` or `lab wording`. When only a reading backs a fault, `check.js` swaps in the lab's own detail.
- The order of each surface's checks is the lab's, not the product's (the sources give none). Say so; do not claim it.
- Only `.example` and `.invalid` hosts in any file. No tenant, client or customer identifiers. The one allowed outside host is the vendor's public docs site in `sources.json`.
- No EC key generation (it aborted Node on CI): RSA only. No `eval`, `Function`, `vm`.
- Netguard blocks outbound calls; Real mode allows exactly one typed host for one request. Mock must keep `attempts` at 0.
- `server/src/health.js` and `server/src/doctor.js` are vendored byte-identical from `AI-DEMO-Standalone/shared/`; never edit them (pins in `vendored.sha256`).
- Pasted tokens: 16 KB cap, never echoed, claims shown through `show()` (escapes control and bidi characters).
- Real mode is a read-only discovery probe, gated by `TI_REAL_PROBE=1`, a confirm, https only, no redirects, size and time caps, SSRF check at connect time.
- No AI attribution in any commit, PR, issue or file.
