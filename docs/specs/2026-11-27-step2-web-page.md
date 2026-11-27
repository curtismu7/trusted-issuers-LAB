# trusted-issuers-LAB step 2: the web page

**Status:** draft   **Owner:** the repo owner

## Goal
Give the Trusted Issuers Tester its web page (README "step 2 of 3"): browse the
4 trust surfaces × 14 issuers matrix, run `/api/check` with any of the 22
break-it mutations, and read the result, the cell's evidence tag and the trust
config — in a browser, through the lab-proxy as well as loopback.

## Shape
Inspector layout per `shared/STANDALONE-UI-PATTERNS.md` §6:
- **Tree column (≈220px):** the 4 surfaces (A–D letters, names from
  `/api/data/surfaces`); under the selected surface, its issuers from
  `/api/data/matrix` (a cell exists per surface×issuer, including `na`).
- **Form column:** the selected cell's status chip + evidence chip + note; the
  mutation picker (22 from `/api/data/breakits`, default `none`); Run check;
  optional paste-a-token box (`pasted: true` is server-enforced to be
  exclusive with mutation); the Real-mode issuer probe panel (visible only when
  `/api/info` says `realAvailable`, otherwise an honest one-line "not
  configured" note).
- **Output column:** the `/api/check` result as Pretty / Wire tabs (`pre.code`);
  cell status, verdict chip (pass/refused from the result), the trustConfig the
  check ran against, and the run's entry in the Runs list (`/api/runs` count).

Shell, banner, chips, buttons, tabs per the pattern doc; theme tokens only;
usable at 375px; dark and light both work. Simulation banner first on the page
(text from `/api/info.simulated`).

## Acceptance criteria (each a runnable check)
1. `docker compose up` serves the page at `/` (not the "has not been built"
   JSON): the Dockerfile builds `web/dist` before `npm ci --omit=dev`, and the
   running container answers `GET /` with HTML.
2. The proxy path `https://local.ping-devops.com:8443/trusted-issuers/` returns
   the same HTML (200), and `GET /api/health` there still returns
   `demo-health/1` `ready`.
3. Selecting surface `pf-idjag` + issuer `pf` and pressing Run check shows the
   cell's `status`, `evidence` and the `trustConfig` the check used; the Wire
   tab shows the same payload as JSON.
4. Choosing mutation `tampered-signature` and running produces a refused
   verdict with the failing check named; `none` on the same cell passes. Both
   runs appear in the Runs list.
5. `GET /` HTML at 375px width shows the tree as a horizontal row and the form
   and output stacked, nothing clipped (Playwright screenshot reviewed).
6. The existing server tests all still pass unchanged
   (`npm test`, Node 26, real counts pasted), plus new web tests for the page's
   data wiring (`web/` vitest or node --test per repo convention).
7. `npm run doctor` passes; `check-ui-patterns.sh` reports no new drift;
   conformance gate `node ~/Development/demo-kit-base/scripts/conformance.mjs
   . --tier=Tester` has no FAIL.
8. Shelf entry unchanged (port 7815, kind Tester); `docs/shelf-entry.json`
   still validates against the shelf registry.

## Unhappy paths (each has a check)
- `/api/data` unreachable or non-JSON → the page shows an error card, not a
  blank screen.
- A cell with status `na` → Run check is disabled with a reason; the tree still
  lists it.
- `pasted: true` with a mutation selected → the server 400s; the page shows the
  server's message verbatim, never a raw stack.
- Real mode not configured → the probe panel renders the honest note; with
  `TI_REAL_PROBE=1` but mock mode, the server's 409 `mock_mode` message is
  shown verbatim.
- Long output (a full check result) → the `pre.code` block scrolls
  horizontally, the layout does not break.
- Reset (`/api/reset`) → Runs list clears and the page reflects it.

## Out of scope
Story mode, diagrams, new server routes, changes to the engine or data, the
step-3 item (whatever the README reserves it for), Real-mode probe
configuration UI.

## Protected / must not break
The API contract (`/api/check` input keys, 400/409 shapes), the host/origin
write guard, loopback-only bind, netguard self-test, the vendored pins, the
existing tests, the Dockerfile's non-root `USER node` and read-only runtime.

## Verification plan
`npm test` (server + new web tests) in the worktree; `docker compose up
--build` on 127.0.0.1:7815; Playwright drive of every acceptance criterion
(375px and 1280px, dark and light); proxy check through
`:8443/trusted-issuers/`; `npm run doctor` + conformance. Owner reviews the
diff and the screenshots before merge.
