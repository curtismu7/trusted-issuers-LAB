import React, { useCallback, useEffect, useMemo, useState } from "react";
import Json from "./components/JsonPane.jsx";
import TopMenu, { applyFontSize } from "./top-menu/TopMenu.jsx";
import TrustDiagram from "./TrustDiagram.jsx";

const STATUS_LABEL = {
  supported: "Supported",
  configurable: "Configurable",
  "not-proven": "Not proven",
  na: "Not applicable",
  unknown: "Unknown",
};

const CHIP_OF = {
  supported: "chip--ok",
  configurable: "chip--warn",
  "not-proven": "chip--warn",
  na: "chip--info",
  unknown: "chip--info",
};

async function jfetch(url, opts) {
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error(body.message || `HTTP ${r.status}`);
    e.code = body.error;
    e.status = r.status;
    throw e;
  }
  return body;
}

const post = (url, data) => jfetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });

export default function App() {
  const [info, setInfo] = useState(null);
  const [sets, setSets] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [surface, setSurface] = useState(null);
  const [issuer, setIssuer] = useState(null);
  const [mutation, setMutation] = useState("none");
  const [pasted, setPasted] = useState("");
  const [usePaste, setUsePaste] = useState(false);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState(null);
  const [probe, setProbe] = useState(null);
  const [probeBusy, setProbeBusy] = useState(false);
  const [probeError, setProbeError] = useState(null);
  const [resetNote, setResetNote] = useState("Nothing run yet — every check below is a fresh, in-process decision.");
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "auto");
  const [fontStep, setFontStep] = useState("M");

  useEffect(() => {
    jfetch("/api/info")
      .then(async (i) => {
        setInfo(i);
        const d = await jfetch("/api/data");
        const wanted = ["surfaces", "issuers", "matrix", "breakits", "evidence"];
        const loaded = await Promise.all(wanted.map(async (id) => ({ id, ...(await jfetch(`/api/data/${id}`)) })));
        setSets(loaded);
        const first = loaded.find((s) => s.id === "surfaces")?.surfaces?.[0];
        if (first) setSurface(first.id);
      })
      .catch((e) => setLoadError(`The lab's data did not load: ${e.message}`));
  }, []);

  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => { applyFontSize(fontStep); }, [fontStep]);

  const surfaces = useMemo(() => sets?.find((s) => s.id === "surfaces")?.surfaces ?? [], [sets]);
  const issuers = useMemo(() => sets?.find((s) => s.id === "issuers")?.issuers ?? [], [sets]);
  const mutations = useMemo(() => sets?.find((s) => s.id === "breakits")?.mutations ?? [], [sets]);
  const cells = useMemo(() => sets?.find((s) => s.id === "matrix")?.cells ?? [], [sets]);
  const evidence = useMemo(() => sets?.find((s) => s.id === "evidence") ?? null, [sets]);

  const cell = useMemo(
    () => cells.find((c) => c.issuer === issuer && c.surface === surface) ?? null,
    [cells, issuer, surface]
  );

  // Issuers for the tree: the ones with a cell on the selected surface, ordered by the issuer list.
  const surfaceIssuers = useMemo(() => {
    const ids = new Set(cells.filter((c) => c.surface === surface).map((c) => c.issuer));
    return issuers.filter((i) => ids.has(i.id));
  }, [cells, surface, issuers]);

  useEffect(() => {
    if (surfaceIssuers.length && !surfaceIssuers.some((i) => i.id === issuer)) setIssuer(surfaceIssuers[0].id);
  }, [surfaceIssuers, issuer]);

  const naCell = cell?.status === "na";

  const run = useCallback(async () => {
    setRunning(true);
    setRunError(null);
    try {
      const body = { surface, issuer, mutation };
      if (usePaste && pasted.trim()) body.token = pasted.trim();
      const r = await post("/api/check", body);
      setResult(r);
      setResetNote(`Last run: ${r.input.issuer} × ${r.input.surface} × ${r.input.mutation} → ${r.verdict}.`);
    } catch (e) {
      setRunError(e.message);
    } finally {
      setRunning(false);
    }
  }, [surface, issuer, mutation, usePaste, pasted]);

  const runProbe = useCallback(async () => {
    setProbeBusy(true);
    setProbeError(null);
    try {
      setProbe(await post("/api/probe", { issuer }));
    } catch (e) {
      setProbeError(e.message);
    } finally {
      setProbeBusy(false);
    }
  }, [issuer]);

  const resetServer = useCallback(async () => {
    try {
      const r = await post("/api/reset", {});
      setResult(null);
      setResetNote(`Reset: ${r.cleared} run${r.cleared === 1 ? "" : "s"} cleared.`);
    } catch (e) {
      setResetNote(`Reset failed: ${e.message}`);
    }
  }, []);

  const surfaceName = surfaces.find((s) => s.id === surface)?.name ?? "";
  const issuerName = issuers.find((i) => i.id === issuer)?.name ?? "";

  return (
    <div className="app">
      <header className="shell-bar">
        <a className="shell-brand" href="/">Trusted Issuers LAB</a>
        <span className="shell-sub">Who trusts whom — a Tester lab</span>
        <span className="shell-spacer" />
        <TopMenu
          mode={{
            value: info?.source === "real" ? "real" : "mock",
            onChange: (v) => post("/api/mode", { source: v }).then(setInfo).catch(() => {}),
            realAvailable: info ? info.realAvailable === true : null,
            realHint: "Real mode needs TI_REAL_PROBE=1 in this app's own .env. Everything here is simulated either way.",
          }}
          theme={{ value: theme, onChange: setTheme }}
          fontSize={{ value: fontStep, onChange: setFontStep }}
          postman={{ repo: "curtismu7/trusted-issuers-LAB", slug: "trusted-issuers-lab" }}
          help={{ href: "https://github.com/curtismu7/trusted-issuers-LAB#readme" }}
          onReset={resetServer}
        />
      </header>

      {loadError && (
        <div className="banner banner--error" role="alert" data-testid="load-error">{loadError}</div>
      )}

      {info?.simulated && (
        <div className="banner" data-testid="sim-banner">{info.banner}</div>
      )}

      <TrustDiagram surfaces={surfaces} />

      <main className="inspector">
        <nav className="panel tree" aria-label="Trust surfaces and issuers" data-testid="tree">
          <ul className="tree__list">
            {surfaces.map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  className="tree__item"
                  aria-selected={s.id === surface}
                  data-testid={`surface-${s.id}`}
                  onClick={() => { setSurface(s.id); setResult(null); setRunError(null); }}
                >
                  <span className="tree__letter">{s.letter}</span> {s.name}
                </button>
                {s.id === surface && (
                  <ul className="tree__sub">
                    {surfaceIssuers.map((i) => (
                      <li key={i.id}>
                        <button
                          type="button"
                          className="tree__item tree__item--sub"
                          aria-selected={i.id === issuer}
                          data-testid={`issuer-${i.id}`}
                          onClick={() => { setIssuer(i.id); setResult(null); setRunError(null); setProbe(null); }}
                        >
                          {i.name}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </nav>

        <section className="panel form" aria-label="Cell and check form" data-testid="form">
          {!cell && <p className="muted">Pick a surface, then an issuer.</p>}
          {cell && (
            <>
              <h1 className="form__title">{issuerName} × {surfaceName}</h1>
              <p className="chips">
                <span className={`tichip ${CHIP_OF[cell.status] ?? "tichip--info"}`} data-testid="cell-status">{STATUS_LABEL[cell.status] ?? cell.status}</span>
                <span className="tichip tichip--info" data-testid="cell-evidence">evidence: {cell.evidence}</span>
              </p>
              <p className="muted" data-testid="cell-note">{cell.note}</p>

              {evidence && (
                <details className="evidence-note">
                  <summary>What the evidence tag means</summary>
                  <dl className="kv">
                    {(evidence.tags ?? []).map((t) => (
                      <div key={t.id ?? t.tag ?? t.name}><dt>{t.id ?? t.tag ?? t.name}</dt><dd>{t.what ?? t.meaning ?? ""}</dd></div>
                    ))}
                  </dl>
                </details>
              )}

              <fieldset className="field">
                <legend>Break it</legend>
                <label className="field__label" htmlFor="mutation">Mutation applied to the token before the check</label>
                <select id="mutation" className="select" value={mutation} onChange={(e) => { setMutation(e.target.value); setResult(null); }} disabled={naCell || usePaste} data-testid="mutation">
                  {mutations.map((m) => (
                    <option key={m.id} value={m.id}>{m.label}</option>
                  ))}
                </select>
                {mutations.find((m) => m.id === mutation) && !usePaste && (
                  <p className="muted" data-testid="mutation-what">{mutations.find((m) => m.id === mutation).what}</p>
                )}
              </fieldset>

              <fieldset className="field">
                <legend>Or paste your own token</legend>
                <label className="check">
                  <input type="checkbox" checked={usePaste} onChange={(e) => { setUsePaste(e.target.checked); setResult(null); }} disabled={naCell} data-testid="use-paste" />
                  Check a token I paste instead of a minted one
                </label>
                {usePaste && (
                  <textarea
                    className="textarea"
                    rows={4}
                    placeholder="Paste a JWT minted for this surface…"
                    value={pasted}
                    onChange={(e) => { setPasted(e.target.value); setResult(null); }}
                    data-testid="paste-box"
                  />
                )}
                {usePaste && mutation !== "none" && (
                  <p className="muted" data-testid="paste-note">A pasted token is checked as it is — the server refuses a paste together with a break-it, so the mutation picker is off.</p>
                )}
              </fieldset>

              <button type="button" className="primary" onClick={run} disabled={running || naCell} data-testid="run">
                {running ? "Running…" : "Run check"}
              </button>
              {naCell && <p className="muted" data-testid="na-reason">This cell is not applicable: there is nothing for this issuer to trust on this surface.</p>}
              {runError && <p className="error" role="alert" data-testid="run-error">{runError}</p>}

              {info?.realAvailable === true ? (
                <div className="real">
                  <h2 className="h2">Issuer discovery probe <span className="tichip tichip--ok">REAL</span></h2>
                  <p className="muted">Read-only: fetches the issuer's discovery document and keys from your own network. Nothing is minted or stored.</p>
                  <button type="button" className="" onClick={runProbe} disabled={probeBusy} data-testid="probe-run">{probeBusy ? "Probing…" : "Probe this issuer"}</button>
                  {probeError && <p className="error" role="alert" data-testid="probe-error">{probeError}</p>}
                  {probe && <Json value={probe} label="Probe result" testId="probe" />}
                </div>
              ) : (
                <p className="muted" data-testid="real-off">Real mode is not configured on this install (TI_REAL_PROBE=1 in the app's own .env enables the read-only issuer probe). The matrix and checks are unaffected.</p>
              )}
            </>
          )}
        </section>

        <section className="panel output" aria-label="Check result" data-testid="output">
          {!result && !runError && <p className="muted">The check result appears here: the verdict, the trust config it ran against, the minted (or pasted) token and the response the surface returned.</p>}
          {result && (
            <>
              <p className="chips" data-testid="verdict-line">
                <span className={`tichip ${result.verdict === "accepted" ? "tichip--ok" : "tichip--danger"}`} data-testid="verdict">{result.verdict}</span>
                <span className={`tichip ${result.matchesExpected ? "tichip--ok" : "tichip--warn"}`} data-testid="matches">matches expectation: {String(result.matchesExpected)}</span>
                <span className="tichip tichip--info">{result.checks.filter((c) => c.pass).length}/{result.checks.length} checks passed</span>
              </p>
              <p data-testid="lesson">{result.lesson}</p>
              <Json value={result} label="Check result" testId="result" />
            </>
          )}
        </section>
      </main>

      <footer className="statusline">
        <span data-testid="reset-note">{resetNote}</span>
      </footer>
    </div>
  );
}
