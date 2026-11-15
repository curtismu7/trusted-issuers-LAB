# Trusted Issuers LAB

**Tier: Tester.** Who trusts whom. A token from another issuer is trusted in four different places, with four different settings, and people mix them up. This lab puts them side by side: the four places, fourteen kinds of issuer, what each pairing needs, and when to use which. Mock only. It mints its own tokens, signs them with its own keys and checks them with real RS256 verification, so you can break one thing at a time and see which check catches it.

Repo: https://github.com/curtismu7/trusted-issuers-LAB

> **Step 1 of 3.** This is the core: the content, the engine, the API and the tests. The web page is built in step 2.

## The four places

| | Where the trust is set | What it accepts |
|---|---|---|
| **A** | PingOne token exchange: Integrations > Trusted Issuers, assigned to an application | A signed JWT as the subject or actor token of an RFC 8693 exchange. PingOne then mints its own token. |
| **B** | PingOne Authorize: External OAuth Servers, with the audience on the API service | A signed access token from another authorization server, checked before a request reaches your API. |
| **C** | PingOne Privilege: Federated Identity (API name NonHumanIdentity) | An agent's or workload's own platform token, with no stored secret. |
| **D** | PingFederate: an IdP connection per trusted issuer (ID-JAG) | An identity assertion for a signed-in person, issued by another IdP. |

Fourteen issuers: another PingOne environment, PingFederate, PingAM, Okta, Auth0, Microsoft Entra ID (v1.0 and v2.0), a generic RFC 9068 server, a Kubernetes API server, AWS EKS OIDC, GitHub Actions, GitLab CI, SPIFFE/SPIRE, the Privilege Docker sensor (self-signed) and your own signer. That is 56 pairings, and every one has a status, an evidence tag, a source and the exact configuration you would enter.

## Evidence: nothing here is stated without a source

Every fact carries one of five tags and a source. The page shows both.

| Tag | Meaning |
|---|---|
| DOCS | A vendor's published documentation or release note (page and revision date given). |
| MEASURED | Run or read by us on a real system on a given date. Our note, not a vendor statement. |
| DECK | A claim in a Ping presentation, not checked on our tenant. |
| LAB READING | Our reading of a schema, a sibling lab or a vendor sample. An inference. |
| UNVERIFIED | No source found. |

A pairing is marked **supported** only with DOCS or MEASURED evidence. The PingOne measurements date from 2026-10-27, before the feature went generally available, and have not been re-run. Gateway acceptance of a PingFederate workload token on the Privilege MCP route is **not proven** on our tenant. Product wording (an error text) is shown as the product's only when it came from the docs or a measurement; otherwise it is labelled lab wording.

## When do we use it

`data/decide.json` is a short question tree (where is the token checked, what is calling, is there a person, one-off or standing). `data/seen-in.json` lists the labs of ours that show each trust, the file we read to confirm it, and the gaps: demos that should use it and do not.

## Run

Docker (OrbStack):

```
docker compose up --build        # http://127.0.0.1:7818
```

Without Docker (Node 26):

```
npm ci
npm start                        # http://127.0.0.1:7818
npm test
npm run doctor
npm run reset
```

## Ports, and what to do if the port is taken

```
Ports: trusted-issuers-LAB listens on 7818 (set with PORT, default 7818).

If the port is taken:
1. Find what is using it:
   lsof -iTCP:7818 -sTCP:LISTEN -n -P
2. If it is an old copy of this app, stop it: kill <PID>.
3. If it is something else, stop it, or start this app on another port in 7800-7999:
   PORT=7830 npm start
```

## API

| Route | What it does |
|---|---|
| `GET /api/health` | `demo-health/1`. |
| `GET /api/info` | Mode (`source`, `realAvailable`), counts, the evidence census. |
| `POST /api/mode` | Exactly `{ "source": "mock" \| "real" }`. Real not configured answers 409 and names what is missing. |
| `GET /api/data/{evidence,sources,surfaces,issuers,matrix,breakits,decide,seen-in}` | The content. `GET /api/data/matrix/:issuer/:surface` is one cell with its configuration. |
| `POST /api/check` | `{ issuer, surface, mutation?, overrides?, token?, tokenType? }`. Mints a MOCK-ISSUED token (with at most one fault) or checks a pasted one, and returns each check's result, the refusal and where its wording comes from. |
| `POST /api/probe` | Real mode only: the issuer discovery probe (below). |
| `POST /api/reset`, `GET /api/runs`, `GET /api/netguard` | Clear the run log, list it, show the outbound-call evidence. |

Tokens are shown raw and labelled MOCK-ISSUED (this is education). Nothing in the app holds a credential.

## Mock and Real

**Mock** (the default) needs nothing and makes no outbound call. A guard blocks every lookup and connect that is not loopback, with a self-test, and a test asserts zero attempts.

**Real** is optional and owner-run. Set `TI_REAL_PROBE=1` in the `.env` beside `docker-compose.yml`. It is a read-only probe: for one https issuer URL you type and confirm, it fetches the discovery document (OIDC, then RFC 8414) and compares the Issuer string you would paste with the document's `issuer`, character for character. No redirects, 64 KB and 5 s caps, no private addresses, no credentials. Real is off in the Docker image until you set it.

## Safety

Loopback bind, Host check, same-origin JSON writes, Docker publishes `127.0.0.1` only. Anything a visitor pastes is bounded, parsed without `eval`, and shown with control and bidirectional characters turned into visible escapes. Every host in the data is on `.example` or `.invalid`. RSA keys only.

## What this lab does not claim

- It is not PingOne, PingFederate or Privilege. It applies each product's documented or measured rules to tokens it made itself.
- The order of each surface's checks is the lab's: the sources do not state one. The break-its break one thing at a time for that reason.
- Where a source is silent the cell says UNVERIFIED. Check before quoting.

Vendored unchanged from the family's shared code: `server/src/health.js` and `server/src/doctor.js` (sha256 pins in `server/src/vendored.sha256`).
