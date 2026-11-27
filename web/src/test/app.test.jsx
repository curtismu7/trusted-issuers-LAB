// App wiring tests with a fake fetch: the page renders the matrix, runs a check, surfaces errors honestly.
// No network: fetch is replaced per test; the shapes come from the real API contract.
import { render, screen, within, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import React from "react";
import App from "../App.jsx";

const INFO = {
  app: "trusted-issuers", name: "Trusted Issuers LAB", tier: "Tester", version: "0.1.0",
  source: "mock", realAvailable: false, simulated: true, banner: "SIMULATED: every token here is minted and checked inside this app with its own keys.",
};

const SURFACES = [
  { id: "p1-exchange", letter: "A", name: "PingOne token exchange: trusted issuers" },
  { id: "pf-idjag", letter: "D", name: "PingFederate: ID-JAG trusted IdP" },
];
const ISSUERS = [
  { id: "p1-env", name: "Another PingOne environment" },
  { id: "pf", name: "PingFederate" },
  { id: "okta", name: "Okta" },
];
const CELLS = [
  { issuer: "p1-env", surface: "p1-exchange", status: "supported", evidence: "docs", source: "p1-ti-exchange", note: "Named in the docs." },
  { issuer: "okta", surface: "p1-exchange", status: "configurable", evidence: "docs", source: "p1-ti-exchange", note: "Third-party issuers are configurable." },
  { issuer: "pf", surface: "p1-exchange", status: "na", evidence: "unverified", source: "p1-ti-exchange", note: "Not applicable here." },
  { issuer: "pf", surface: "pf-idjag", status: "supported", evidence: "measured", source: "pf-idjag", note: "Measured on a real tenant." },
];
const MUTATIONS = [
  { id: "none", label: "Nothing wrong", what: "A well-formed token.", teaches: "The baseline." },
  { id: "tampered-signature", label: "Tampered signature", what: "One byte of the signature flipped.", teaches: "Signatures bind claims." },
];
const EVIDENCE = { tags: [{ id: "docs", what: "Written in product docs." }, { id: "measured", what: "Ran against a real tenant." }] };

const EVIDENCE_SET = { id: "evidence", ...EVIDENCE };
const SURFACES_SET = { id: "surfaces", surfaces: SURFACES };
const ISSUERS_SET = { id: "issuers", issuers: ISSUERS };
const MATRIX_SET = { id: "matrix", cells: CELLS };
const BREAKITS_SET = { id: "breakits", mutations: MUTATIONS };
const DATA_IDS = ["evidence", "surfaces", "issuers", "matrix", "breakits"];
const SETS = { evidence: EVIDENCE_SET, surfaces: SURFACES_SET, issuers: ISSUERS_SET, matrix: MATRIX_SET, breakits: BREAKITS_SET };
const DATA = { sets: DATA_IDS };

const CHECK_OK = { input: { issuer: "p1-env", surface: "p1-exchange", mutation: "none", tokenType: "t", pasted: false }, now: 1,
  cell: CELLS[0], trustConfig: { trustedIssuer: { issuer: "https://x.example" } }, token: { raw: "a.b.c", label: "mock" },
  header: { alg: "RS256", typ: "JWT", kid: "k1" }, claims: { iss: "https://x.example" }, verdict: "accepted",
  checks: [{ pass: true }, { pass: true }], response: { http: 200, body: {} }, lesson: "The baseline: every check passes.",
  expected: { verdict: "accepted" }, matchesExpected: true };

function fakeFetch(routes) {
  return vi.fn(async (url, opts) => {
    const hit = routes[url] ?? routes[url.split("?")[0]];
    if (!hit) throw new Error(`unexpected fetch ${url}`);
    if (hit.fail) return { ok: false, status: hit.status ?? 400, json: async () => hit.body ?? { error: "bad", message: hit.fail } };
    return { ok: true, status: 200, json: async () => (typeof hit === "function" ? hit(opts ? JSON.parse(opts.body) : undefined) : hit) };
  });
}

beforeEach(() => {
  globalThis.fetch = fakeFetch({
    "/api/info": INFO,
    "/api/data": DATA,
    ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("App: the matrix and the run", () => {
  test("renders the surfaces, issuers of the first surface, cell status and the simulation banner", async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("cell-status")).toBeInTheDocument());
    expect(screen.getByTestId("sim-banner")).toHaveTextContent("SIMULATED");
    expect(screen.getByTestId("surface-p1-exchange")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("issuer-p1-env")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("cell-status")).toHaveTextContent("Supported");
    expect(screen.getByTestId("cell-evidence")).toHaveTextContent("evidence: docs");
    expect(screen.getByTestId("cell-note")).toHaveTextContent("Named in the docs.");
  });

  test("running the check posts the picked cell and shows verdict, lesson and result", async () => {
    const run = vi.fn(() => CHECK_OK);
    globalThis.fetch = fakeFetch({ "/api/info": INFO, "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])), "/api/check": run });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.click(screen.getByTestId("run"));
    expect(await screen.findByTestId("verdict")).toHaveTextContent("accepted");
    expect(screen.getByTestId("matches")).toHaveTextContent("true");
    expect(screen.getByTestId("lesson")).toHaveTextContent("baseline");
    expect(run).toHaveBeenCalled();
  });

  test("a mutation choice travels in the POST body", async () => {
    let seen;
    globalThis.fetch = fakeFetch({
      "/api/info": INFO, "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
      "/api/check": (body) => { seen = body; return CHECK_OK; },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.change(screen.getByTestId("mutation"), { target: { value: "tampered-signature" } });
    fireEvent.click(screen.getByTestId("run"));
    await screen.findByTestId("verdict");
    expect(seen.mutation).toBe("tampered-signature");
  });

  test("an na cell disables Run and says why; its issuer still shows in the tree", async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.click(screen.getByTestId("issuer-pf"));
    expect(screen.getByTestId("cell-status")).toHaveTextContent("Not applicable");
    expect(screen.getByTestId("run")).toBeDisabled();
    expect(screen.getByTestId("na-reason")).toBeInTheDocument();
  });

  test("paste mode: the token goes in the body and the mutation picker is disabled", async () => {
    let seen;
    globalThis.fetch = fakeFetch({
      "/api/info": INFO, "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
      "/api/check": (body) => { seen = body; return CHECK_OK; },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.click(screen.getByTestId("use-paste"));
    expect(screen.getByTestId("mutation")).toBeDisabled();
    fireEvent.change(screen.getByTestId("paste-box"), { target: { value: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJoIn0.c2ln" } });
    fireEvent.click(screen.getByTestId("run"));
    await screen.findByTestId("verdict");
    expect(seen.token).toBe("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJoIn0.c2ln");
    expect(seen.mutation).toBe("none");
  });

  test("a server refusal is shown verbatim, not a stack", async () => {
    globalThis.fetch = fakeFetch({
      "/api/info": INFO, "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
      "/api/check": { fail: "Give a token or a break-it, not both.", status: 400 },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.click(screen.getByTestId("use-paste"));
    fireEvent.change(screen.getByTestId("paste-box"), { target: { value: "x.y.z" } });
    fireEvent.click(screen.getByTestId("run"));
    expect(await screen.findByTestId("run-error")).toHaveTextContent("Give a token or a break-it, not both.");
  });

  test("data that fails to load shows an error card, not a blank page", async () => {
    globalThis.fetch = fakeFetch({ "/api/info": INFO, "/api/data": { fail: "boom", status: 500 } });
    render(<App />);
    expect(await screen.findByTestId("load-error")).toHaveTextContent("did not load");
    expect(screen.getByRole("banner") ?? screen.getByTestId("load-error")).toBeInTheDocument();
  });

  test("real mode: the probe panel appears only when realAvailable, and probes the picked issuer", async () => {
    let seen;
    globalThis.fetch = fakeFetch({
      "/api/info": { ...INFO, realAvailable: true },
      "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
      "/api/probe": (body) => { seen = body; return { issuer: body.issuer, discovery: "ok" }; },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("probe-run")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("probe-run"));
    await screen.findByTestId("probe-box");
    expect(seen.issuer).toBe("p1-env");
  });

  test("real mode off: an honest note instead of the panel", async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("real-off")).toBeInTheDocument());
    expect(screen.queryByTestId("probe-run")).toBeNull();
  });

  test("reset clears the result and says so", async () => {
    let resetHit = false;
    globalThis.fetch = fakeFetch({
      "/api/info": INFO, "/api/data": DATA, ...Object.fromEntries(DATA_IDS.map((id) => [`/api/data/${id}`, SETS[id]])),
      "/api/check": CHECK_OK,
      "/api/reset": () => { resetHit = true; return { ok: true, reset: true, cleared: 2 }; },
    });
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("run")).toBeEnabled());
    fireEvent.click(screen.getByTestId("run"));
    await screen.findByTestId("verdict");
    fireEvent.click(screen.getByTestId("reset"));
    await waitFor(() => expect(screen.queryByTestId("verdict")).toBeNull());
    expect(resetHit).toBe(true);
    expect(screen.getByTestId("reset-note")).toHaveTextContent("2 runs cleared");
  });
});
