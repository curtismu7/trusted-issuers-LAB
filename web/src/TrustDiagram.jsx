import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, useEdgesState, useNodesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// The trust-flow: a token minted by an external issuer travels to one of the four trust surfaces, which checks it
// (issuer, signature, time claims, audiences) and answers accepted or refused. Boxes are draggable; Reset puts them
// back; Simulate walks the checks in the order the engine runs them (the lab's own measured order). The caption says
// in words what the picture shows.

const SPEEDS = [["0.5", "0.5x"], ["1", "1x"], ["2", "2x"], ["4", "4x"]];
const BASE_MS = 1600;

export const START_NODES = [
  { id: "issuer", type: "box", position: { x: 0, y: 140 }, data: { title: "External issuer", sub: "Mints a signed JWT: iss, aud, exp, iat and a signature from its own key." } },
  { id: "surface", type: "box", position: { x: 380, y: 140 }, data: { title: "Trust surface", sub: "PingOne token exchange, PingOne Authorize, Privilege Federated Identity or PingFederate ID-JAG." } },
  { id: "config", type: "box", position: { x: 380, y: 0 }, data: { title: "Trusted-issuer config", sub: "The issuer string, its key set, the audiences and the require switches." } },
  { id: "decision", type: "box", position: { x: 760, y: 140 }, data: { title: "Decision", sub: "accepted, or refused with the failing check named." } },
];
export const START_EDGES = [
  { id: "present", source: "issuer", target: "surface", sourceHandle: "r", targetHandle: "l", label: "presents the JWT" },
  { id: "lookup", source: "surface", target: "config", sourceHandle: "t", targetHandle: "b", label: "reads the trust config" },
  { id: "checks", source: "config", target: "decision", sourceHandle: "r", targetHandle: "t", label: "every check in order" },
  { id: "answer", source: "surface", target: "decision", sourceHandle: "r2", targetHandle: "l", label: "accepted or refused" },
];

// The check order the engine runs (surface A's measured order; the other surfaces share its shape).
const SIM_STEPS = [
  { say: "The issuer mints a signed JWT for this surface: iss, aud, exp, iat and a signature from its key set." },
  { say: "The surface reads its trusted-issuer config: the issuer string, the key set, the audiences, the require switches." },
  { say: "The token type must name a JWT, the issuer must be assigned and byte for byte known, the signature must verify." },
  { say: "The time claims are checked against the require switches, the clock skew and the max future validity, then the audience." },
  { say: "The decision: accepted, or refused with the failing check named in the response." },
];

const POS = { l: Position.Left, r: Position.Right, t: Position.Top, b: Position.Bottom, r2: Position.Right, l2: Position.Left };
const OFFSET = { l: "35%", r: "35%", l2: "72%", r2: "72%", t: "20%", b: "80%" };

function Box({ data }) {
  return (
    <div className={`tibox${data.on ? " tibox--on" : ""}${data.dim ? " tibox--dim" : ""}`}>
      {Object.entries(POS).map(([id, pos]) => (
        <Handle key={id} id={id} type="source" position={pos} style={OFFSET[id] ? (pos === Position.Left || pos === Position.Right ? { top: OFFSET[id] } : { left: OFFSET[id] }) : undefined} />
        ))}
      <strong>{data.title}</strong>
      <span>{data.sub}</span>
    </div>
  );
}
const nodeTypes = { box: Box };

export default function TrustDiagram({ surfaces }) {
  const [nodes, setNodes, onNodesChange] = useNodesState(START_NODES);
  const [edges, setEdges] = useEdgesState(START_EDGES);
  const [step, setStep] = useState(-1);
  const [running, setRunning] = useState(false);
  const [speed, setSpeed] = useState("1");

  const surfaceName = surfaces?.[0]?.name ?? "the trust surface";
  useEffect(() => {
    setNodes(START_NODES.map((n) => (n.id === "surface" ? { ...n, data: { ...n.data, sub: surfaceName } } : n)));
  }, [surfaceName, setNodes]);

  useEffect(() => {
    if (!running) return undefined;
    let i = step < 0 ? 0 : step + 1;
    if (i >= SIM_STEPS.length) { setRunning(false); return undefined; }
    const t = setTimeout(() => { setStep(i); }, BASE_MS / Number(speed));
    return () => clearTimeout(t);
  }, [running, step, speed]);

  const simulate = useCallback(() => { setStep(-1); setRunning(true); }, []);
  const reset = useCallback(() => { setRunning(false); setStep(-1); setNodes(START_NODES.map((n) => (n.id === "surface" ? { ...n, data: { ...n.data, sub: surfaceName } } : n))); setEdges(START_EDGES); }, [surfaceName, setNodes, setEdges]);

  const styledNodes = useMemo(() => nodes.map((n) => {
    const on = step >= 0 && (
      (n.id === "issuer" && step === 0) ||
      (n.id === "config" && step === 1) ||
      (n.id === "surface" && (step === 2 || step === 4)) ||
      (n.id === "decision" && step === 4));
    const dim = step >= 0 && !on;
    return { ...n, data: { ...n.data, on, dim } };
  }), [nodes, step]);

  const styledEdges = useMemo(() => edges.map((e) => ({
    ...e,
    animated: running && (
      (e.id === "present" && step >= 0) ||
      (e.id === "lookup" && step >= 1) ||
      (e.id === "checks" && step >= 2) ||
      (e.id === "answer" && step >= 4)),
    labelStyle: step >= 0 && (e.id === "present" && step === 0) || (e.id === "lookup" && step === 1) || (e.id === "checks" && step === 2) || (e.id === "answer" && step === 4) ? { fontWeight: 700 } : undefined,
    markerEnd: MarkerType.ArrowClosed,
  })), [edges, step, running]);

  return (
    <div className="tidia" data-testid="diagram">
      <div className="tidia__bar">
        <button type="button" onClick={simulate} data-testid="diagram-simulate">{running ? "Pause" : "Simulate"}</button>
        <button type="button" onClick={() => setRunning(false)} disabled={!running} data-testid="diagram-pause">Pause</button>
        <button type="button" onClick={reset} data-testid="diagram-reset">Reset</button>
        <label>Speed
          <select value={speed} onChange={(e) => setSpeed(e.target.value)} data-testid="diagram-speed">
            {SPEEDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <span className="tidia__caption">{step >= 0 ? SIM_STEPS[Math.min(step, SIM_STEPS.length - 1)].say : "A token from an external issuer is checked against a trust config; the picture walks the checks in the order the engine runs them."}</span>
      </div>
      <div className="tidia__canvas">
        <ReactFlow
          nodes={styledNodes}
          edges={styledEdges}
          onNodesChange={onNodesChange}
          nodeTypes={nodeTypes}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
