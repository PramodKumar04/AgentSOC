// The interactive canvas. Loaded on demand so other pages do not pay for it. Node selection
// uses real buttons; every edge is also available in the connections table for keyboard users.
import {
  Background, BaseEdge, Controls, EdgeLabelRenderer, Handle, MarkerType, Position, ReactFlow, getBezierPath,
  type Edge, type EdgeProps, type EdgeTypes, type Node, type NodeProps, type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Server, User } from "lucide-react";
import { createContext, useContext, useMemo } from "react";

import type { IncidentGraph, NodeRole } from "@/lib/api";
import { cn } from "@/lib/utils";
import { buildFlow, type EdgeState, type FlowEdgeData, type FlowNodeData, type GraphSelection } from "./graph-model";

const SelectContext = createContext<(selection: GraphSelection) => void>(() => undefined);

export const ROLE_LABEL: Record<NodeRole, string> = {
  PRINCIPAL: "Principal", ADMIN: "Admin", SENSITIVE: "Sensitive", JUMP_HOST: "Jump host",
  CHOKE_POINT: "Choke point", ACCOUNT_SWITCH: "Account switch", AMBIGUOUS_SWITCH: "Weak evidence",
};

const STROKE: Record<EdgeState, { stroke: string; strokeWidth: number; strokeDasharray?: string; opacity?: number }> = {
  default: { stroke: "#475569", strokeWidth: 1.75 },
  dimmed: { stroke: "#94a3b8", strokeWidth: 1.25, opacity: 0.45 },
  "path-observed": { stroke: "#2563eb", strokeWidth: 3.5 },
  "path-inferred": { stroke: "#7c3aed", strokeWidth: 3.5, strokeDasharray: "9 6" },
  "path-ambiguous": { stroke: "#b45309", strokeWidth: 3.5, strokeDasharray: "2 7" },
};

function strokeFor(data: FlowEdgeData) {
  if (data.state !== "default") return STROKE[data.state];
  if (data.link.kind === "ATTEMPT") return { stroke: "#dc2626", strokeWidth: 1, strokeDasharray: "1 4" };
  if (data.link.kind === "ACCOUNT") return { stroke: "#cbd5e1", strokeWidth: 1 };
  return STROKE.default;
}

function EvidenceEdge(props: EdgeProps<Edge<FlowEdgeData>>) {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, data } = props;
  const [path, labelX, labelY] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  if (!data) return null;
  const count = data.link.event_ids.length;
  const label = data.link.kind === "ATTEMPT" ? `✕ failed${count > 1 ? ` ×${count}` : ""}`
    : data.link.kind === "MOVEMENT" && count > 1 ? `×${count}` : null;
  const style = { ...strokeFor(data), ...(data.selected ? { strokeWidth: 4 } : {}) };
  return (
    <>
      <BaseEdge id={props.id} path={path} markerEnd={markerEnd} style={style} interactionWidth={22} />
      {label && data.state !== "dimmed" && (
        <EdgeLabelRenderer>
          <span style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
            className="pointer-events-none absolute rounded-sm bg-surface px-1 text-[10px] font-medium text-ink-2">
            {label}
          </span>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

function describe(data: FlowNodeData): string {
  const { node } = data;
  const roles = node.roles.map((r) => ROLE_LABEL[r]).join(", ");
  return `${node.kind === "host" ? "Host" : "Account"} ${node.label}, ${node.event_count} events${roles ? `, ${roles}` : ""}`;
}

function EntityNode({ data }: NodeProps<Node<FlowNodeData>>) {
  const select = useContext(SelectContext);
  const { node } = data;
  const Icon = node.kind === "host" ? Server : User;
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={{ opacity: 0 }} />
      <button type="button" aria-pressed={data.selected} aria-label={describe(data)}
        onClick={() => select({ kind: "node", id: node.node_id })}
        className={cn("nodrag nopan flex size-full flex-col justify-center gap-1 border bg-surface px-2.5 text-left transition-opacity",
          node.kind === "host" ? "rounded-lg" : "rounded-full border-dashed px-4",
          data.selected ? "border-brand ring-2 ring-brand/40" : data.onPath ? "border-brand" : "border-border-strong",
          data.dimmed && "opacity-50")}>
        <span className="flex min-w-0 items-center gap-1.5">
          <Icon className="size-3.5 shrink-0 text-muted" aria-hidden />
          <span className="truncate font-mono text-[12px] font-medium text-ink" title={node.label}>{node.label}</span>
        </span>
        {(node.roles.length > 0 || data.localEvents > 0) && (
          <span className="flex flex-wrap gap-1">
            {node.roles.map((r) => (
              <span key={r} className={cn("rounded-sm px-1 text-[10px] leading-4 font-medium",
                r === "AMBIGUOUS_SWITCH" ? "bg-warn-soft text-warn" : r === "SENSITIVE" ? "bg-critical-soft text-critical" : "bg-low-soft text-ink-2")}>
                {ROLE_LABEL[r]}
              </span>
            ))}
            {data.localEvents > 0 && <span className="rounded-sm bg-low-soft px-1 text-[10px] leading-4 text-ink-2">Local ×{data.localEvents}</span>}
          </span>
        )}
      </button>
      <Handle type="source" position={Position.Right} isConnectable={false} style={{ opacity: 0 }} />
    </>
  );
}

const nodeTypes: NodeTypes = { entity: EntityNode };
const edgeTypes: EdgeTypes = { evidence: EvidenceEdge };

export default function AttackGraphCanvas({ graph, showAccounts, showAttempts, pathId, selection, onSelect }: {
  graph: IncidentGraph; showAccounts: boolean; showAttempts: boolean; pathId: string | null;
  selection: GraphSelection; onSelect: (selection: GraphSelection) => void;
}) {
  const { nodes, edges } = useMemo(() => {
    const flow = buildFlow(graph, { showAccounts, showAttempts, pathId, selection });
    return {
      nodes: flow.nodes.map((n): Node<FlowNodeData> => ({ ...n, type: "entity", style: { width: n.width, height: n.height } })),
      edges: flow.edges.map((e): Edge<FlowEdgeData> => {
        const color = strokeFor(e.data).stroke;
        return { ...e, type: "evidence", ariaLabel: `${e.data.link.kind} link, ${e.data.link.event_ids.length} events`,
                 markerEnd: e.data.link.kind === "ACCOUNT" ? undefined : { type: MarkerType.ArrowClosed, color } };
      }),
    };
  }, [graph, showAccounts, showAttempts, pathId, selection]);

  return (
    <SelectContext.Provider value={onSelect}>
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={{ padding: 0.04 }} minZoom={0.2}
        nodesDraggable={false} nodesConnectable={false} nodesFocusable={false} edgesFocusable={false}
        elementsSelectable={false} onEdgeClick={(_, edge) => onSelect({ kind: "link", id: edge.id })}
        onPaneClick={() => onSelect(null)}>
        <Background gap={20} size={1} color="#e3e6eb" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </SelectContext.Provider>
  );
}
