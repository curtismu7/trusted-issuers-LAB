import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, BaseEdge, Controls, getBezierPath, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { EdgeLabels, FitOpen, Passport, PassportActions } from "./diagram-kit/DiagramKit.jsx";
import { boxPassport, sidePoint } from "./diagram-kit/diagramKit.js";
import "./diagram-kit/diagram-kit.css";

// The trust-flow, on the family's diagram standard (poppy's PatternDiagram pattern): every arrow's label is drawn by the
// vendored diagram-kit above the boxes, clear of each other; clicking a box expands it in place with its passport (group,
// reach, arrows in and out); the walkthrough bar is Simulate / Pause / Reset with a speed control; the caption says in words
// what the picture shows.

const FIT = { padding: 0.08 };
const SPEEDS = [["0.5", "0.5x"], ["1", "1x"], ["2", "2x"], ["4", "4x"]];
const BASE_MS = 1600;
const HANDLES = [["t", Position.Top], ["b", Position.Bottom], ["l", Position.Left], ["r", Position.Right]];

export const GRAPH = {
  nodes: [
    { id: "issuer", label: "External issuer", sub: ["Mints a signed JWT: iss, aud, exp, iat and a signature from its own key."], group: "party", groupLabel: "The other party" },
    { id: "surface", label: "Trust surface", sub: ["PingOne token exchange, PingOne Authorize, Privilege Federated Identity or PingFederate ID-JAG."], group: "ping", groupLabel: "The Ping product" },
    { id: "config", label: "Trusted-issuer config", sub: ["The issuer string, its key set, the audiences and the require switches."], group: "ping", groupLabel: "The Ping product" },
    { id: "decision", label: "Decision", sub: ["accepted, or refused with the failing check named."], group: "out", groupLabel: "The outcome" },
  ],
  edges: [
    { id: "e0", source: "issuer", target: "surface", label: "presents the JWT" },
    { id: "e1", source: "surface", target: "config", label: "reads the trust config" },
    { id: "e2", source: "config", target: "decision", label: "every check in order" },
    { id: "e3", source: "surface", target: "decision", label: "accepted or refused" },
  ],
  groups: { party: { label: "The other party", color: "var(--status-info)" }, ping: { label: "The Ping product", color: "var(--accent)" }, out: { label: "The outcome", color: "var(--status-ok)" } },
};

export const START_POSITIONS = {
  issuer: { x: 0, y: 200 },
  config: { x: 380, y: 20 },
  surface: { x: 380, y: 200 },
  decision: { x: 760, y: 200 },
};

// The check order the engine runs (surface A's measured order; the other surfaces share its shape).
const SIM_STEPS = [
  { edge: "e0", say: "The issuer mints a signed JWT for this surface: iss, aud, exp, iat and a signature from its key set." },
  { edge: "e1", say: "The surface reads its trusted-issuer config: the issuer string, the key set, the audiences, the require switches." },
  { edge: "e2", say: "The token type must name a JWT, the issuer must be assigned and byte for byte known, the signature must verify." },
  { edge: "e2", say: "The time claims are checked against the require switches, the clock skew and the max future validity, then the audience." },
  { edge: "e3", say: "The decision: accepted, or refused with the failing check named in the response." },
];

function Box({ data }) {
  return (
    <div className={`pat-node${data.on ? " pat-node--on" : ""}${data.passport ? " dk-open" : ""}`} data-testid={`pat-node-${data.id}`}>
      {HANDLES.map(([k, pos]) => (
        <span key={k}>
          <Handle id={`s-${k}`} type="source" position={pos} className="pat-handle" />
          <Handle id={`t-${k}`} type="target" position={pos} className="pat-handle" />
        </span>
      ))}
      {data.label}
      {data.passport && <Passport p={data.passport} />}
    </div>
  );
}
const nodeTypes = { box: Box };

// The arrow only; EdgeLabels draws the label on the same curve above the boxes.
function ShiftedArrow({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style }) {
  const [path] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  return <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />;
}
const edgeTypes = { arrow: ShiftedArrow };

const pointFor = (box, handle) => {
  const [h] = String(handle).split("@");
  const pt = sidePoint(box, h.split("-")[1]);
  return pt || null;
};

function Canvas({ surfaceName, onMove, stepper, open, setOpen }) {
  const ref = useRef(null);
  const active = stepper.step >= 0 ? SIM_STEPS[stepper.step] : null;
  const nodes = GRAPH.nodes.map((n) => ({
    id: n.id, type: "box", position: START_POSITIONS[n.id], draggable: true, zIndex: n.id === open ? 10 : undefined,
    data: { id: n.id, label: n.label, kind: n.group, on: !!active && [active.edge && GRAPH.edges.find((e) => e.id === active.edge)].some((e) => e && (e.source === n.id || e.target === n.id)), passport: n.id === open ? boxPassport(GRAPH, n.id) : null },
  }));
  const now = stepper.step >= 0 ? stepper.step : -1;
  const edges = GRAPH.edges.map((e, i) => {
    const isNow = active && active.edge === e.id;
    const seen = stepper.step >= 0 && SIM_STEPS.slice(0, stepper.step + 1).some((s) => s.edge === e.id);
    return {
      id: e.id, source: e.source, target: e.target,
      sourceHandle: `s-${e.source === "surface" && e.target === "decision" ? "r" : e.source === "surface" ? "r" : "r"}`,
      targetHandle: `t-${e.target === "surface" ? "l" : e.target === "config" ? "b" : e.target === "decision" && e.source === "config" ? "t" : "l"}`,
      type: "arrow", animated: isNow, data: {},
      className: `pat-edge${isNow ? " pat-edge--now" : ""}${stepper.step >= 0 && !seen ? " pat-edge--dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed },
    };
  });
  const labels = GRAPH.edges.map((e) => ({
    id: e.id, text: e.label, source: e.source, target: e.target,
    sourceHandle: `${edges.find((x) => x.id === e.id).sourceHandle}`, targetHandle: `${edges.find((x) => x.id === e.id).targetHandle}`,
    active: !!active && active.edge === e.id, dim: stepper.step >= 0 && !(active && active.edge === e.id) && !SIM_STEPS.slice(0, stepper.step + 1).some((s) => s.edge === e.id),
  }));
  const actions = useMemo(() => ({
    open: (id) => setOpen(id), close: () => setOpen(null),
    link: (id) => { const u = new URL(window.location.href); u.searchParams.set("box", id); return u.toString(); },
  }), [setOpen]);
  return (
    <div ref={ref} className="pat-canvas" data-testid="pattern-canvas">
      <PassportActions.Provider value={actions}>
        <ReactFlow
          nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
          fitView fitViewOptions={FIT} nodesConnectable={false} minZoom={0.3}
          onNodeClick={(_, n) => setOpen((o) => (o === n.id ? null : n.id))}
          onPaneClick={() => setOpen(null)}
          onNodeDragStop={(_, n) => onMove(n.id, n.position)}
          onNodeDrag={(_, n) => onMove(n.id, n.position)}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} />
          <Controls showInteractive={false} />
          <EdgeLabels items={labels} pointFor={pointFor} fallback={{ w: 150, h: 56 }} />
          <FitOpen open={open} closePadding={FIT.padding} />
        </ReactFlow>
      </PassportActions.Provider>
    </div>
  );
}

export default function TrustDiagram({ surfaces }) {
  const [positions, setPositions] = useState(START_POSITIONS);
  const [open, setOpen] = useState(null);
  const [step, setStep] = useState(-1);
  const [paused, setPaused] = useState(true);
  const [speed, setSpeed] = useState("1");
  const surfaceName = surfaces?.[0]?.name ?? "the trust surface";
  const stepper = useMemo(() => ({
    get step() { return step; },
    get paused() { return paused; },
    goTo: (n) => { setPaused(true); setStep(n); },
  }), [step, paused]);

  useEffect(() => {
    if (paused) return undefined;
    const next = step + 1;
    if (next >= SIM_STEPS.length) { setPaused(true); return undefined; }
    const t = setTimeout(() => setStep(next), BASE_MS / Number(speed));
    return () => clearTimeout(t);
  }, [paused, step, speed]);

  const simulate = useCallback(() => {
    if (step >= SIM_STEPS.length - 1) { setStep(-1); setPaused(false); }
    else { setPaused(false); if (step < 0) setStep(0); }
  }, [step]);
  const pause = useCallback(() => setPaused(true), []);
  const reset = useCallback(() => { setPaused(true); setStep(-1); setOpen(null); setPositions(START_POSITIONS); }, []);

  const onMove = useCallback((id, position) => setPositions((p) => ({ ...p, [id]: position })), []);

  return (
    <div className="tidia" data-testid="diagram">
      <div className="tidia__bar">
        <button type="button" onClick={simulate} data-testid="diagram-simulate">{paused ? "Simulate" : "Pause"}</button>
        <button type="button" onClick={pause} disabled={paused} data-testid="diagram-pause">Pause</button>
        <button type="button" onClick={reset} data-testid="diagram-reset">Reset</button>
        <label>Speed
          <select value={speed} onChange={(e) => setSpeed(e.target.value)} data-testid="diagram-speed">
            {SPEEDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <span className="tidia__caption" role="status">{step >= 0 ? SIM_STEPS[Math.min(step, SIM_STEPS.length - 1)].say : "A token from an external issuer is checked against a trust config; Simulate walks the checks in the order the engine runs them. Click any box for its details."}</span>
      </div>
      <ReactFlowProvider>
        <Canvas surfaceName={surfaceName} onMove={onMove} stepper={stepper} open={open} setOpen={setOpen} />
      </ReactFlowProvider>
    </div>
  );
}
