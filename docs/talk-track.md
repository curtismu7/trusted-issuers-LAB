# Talk track — Trusted Issuers LAB

Four minutes, Mock mode. Say first: "SIMULATED: every token here is minted and checked inside this app with its own keys. Nothing calls PingOne, PingFederate, Privilege or any tenant. Each claim says where it comes from."

1. **The question.** "Who trusts whom? There are four places in the Ping stack where a trusted issuer gets configured — PingOne token exchange, PingOne Authorize external OAuth servers, Privilege Federated Identity, and PingFederate ID-JAG — and fourteen kinds of issuer. That is 56 pairings, and this lab has a status and the exact config for each."
2. **The diagram.** Walk the four nodes: external issuer presents the JWT, the trust surface reads the trusted-issuer config, every check runs in order, accepted or refused. Press **Simulate** and let the walkthrough play; click a box to expand its passport.
3. **Pick a cell.** Surface D, PingFederate ID-JAG, issuer `pf`. Read the form column: the status chip, the evidence tag, and open "What the evidence tag means" — DOCS, MEASURED, DECK, LAB READING, UNVERIFIED. "Every pairing states its evidence; silent sources are UNVERIFIED."
4. **Run it clean.** Mutation `none`, **Run check**: accepted, all checks passed, and the JSON pane shows the trust config the check ran against.
5. **Break one thing.** Pick `tampered-signature`, run again: refused, "JWT signature verification failed", and the decoded token on screen. "Same cell, one broken thing — that is the whole method of this lab. Twenty-two mutations, one at a time."
6. **The lesson line.** Point at it. "Every refusal comes with what it teaches."
7. **What this lab does not claim.** "It is not the products; the check order is the lab's. PingOne measurements date from 2026-10-27 and have not been re-run, and gateway acceptance of a PingFederate workload token on the Privilege MCP route is not proven."

## Notes for the presenter

- Docker: `docker compose up --build` → http://127.0.0.1:7815. Lab proxy: `/trusted-issuers/`.
- Real mode is an optional read-only issuer probe (`TI_REAL_PROBE=1` in the app's own `.env`); without it the toggle answers 409 — say "the matrix and checks are unaffected".
- Paste-a-token and a break-it mutation are mutually exclusive; the picker disables itself.
