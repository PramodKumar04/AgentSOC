// Turns the API's graph into positioned nodes and edges. Positions and styling state only:
// every edge is one server link, and path membership is read from the server's link IDs.
import { graphlib, layout } from "@dagrejs/dagre";

import type { GraphLink, GraphNode, GraphPath, IncidentGraph } from "@/lib/api";

export type EdgeState = "default" | "dimmed" | "path-observed" | "path-inferred" | "path-ambiguous";

export interface FlowNodeData extends Record<string, unknown> {
  node: GraphNode; localEvents: number; dimmed: boolean; onPath: boolean; selected: boolean;
  switchNote: "conditional" | "weak" | null;
}
export interface FlowEdgeData extends Record<string, unknown> { link: GraphLink; state: EdgeState; selected: boolean }
export interface FlowNode { id: string; position: { x: number; y: number }; data: FlowNodeData; width: number; height: number }
export interface FlowEdge { id: string; source: string; target: string; data: FlowEdgeData }

export type GraphSelection = { kind: "node" | "link"; id: string } | null;
export interface FlowOptions { showAccounts: boolean; showAttempts: boolean; pathId: string | null; selection: GraphSelection }

const WIDTH = 176;
const heightOf = (node: GraphNode, local: number) => {
  const chips = node.roles.length + (local > 0 ? 1 : 0);
  return (node.kind === "host" ? 44 : 38) + (chips === 0 ? 0 : chips > 2 ? 44 : 22);
};

function edgeState(link: GraphLink, path: GraphPath | null): EdgeState {
  if (!path) return "default";
  if (!path.link_ids.includes(link.link_id)) return "dimmed";
  if (path.kind === "OBSERVED") return "path-observed";
  return path.ambiguous ? "path-ambiguous" : "path-inferred";
}

export function selectedPath(graph: IncidentGraph, pathId: string | null): GraphPath | null {
  return graph.paths.find((p) => p.path_id === pathId) ?? null;
}

function isVisible(link: GraphLink, options: FlowOptions): boolean {
  if (link.kind === "LOCAL") return false; // shown on its host: a self-link has no direction to draw
  if (link.kind === "ACCOUNT") return options.showAccounts;
  if (link.kind === "ATTEMPT") return options.showAttempts;
  return true;
}

export function buildFlow(graph: IncidentGraph, options: FlowOptions): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const path = selectedPath(graph, options.pathId);
  const links = graph.links.filter((k) => isVisible(k, options));
  const localEvents = new Map(graph.links.filter((k) => k.kind === "LOCAL").map((k) => [k.source, k.event_ids.length]));
  const shown = graph.nodes.filter((n) => n.kind === "host" || options.showAccounts);

  const g = new graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: "LR", nodesep: 22, ranksep: 70, marginx: 8, marginy: 8 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const node of shown) {
    g.setNode(node.node_id, { width: WIDTH, height: heightOf(node, localEvents.get(node.node_id) ?? 0) });
  }
  for (const link of links) g.setEdge(link.source, link.target, {}, link.link_id);
  layout(g);

  const switches = new Map((path?.switches ?? []).map((s) => [`host:${s.host}`, s.ambiguous]));
  const pathHosts = new Set([...(path?.hosts ?? []).map((h) => `host:${h}`), ...(path?.accounts ?? []).map((a) => `user:${a}`)]);
  return {
    nodes: shown.map((node) => {
      const placed = g.node(node.node_id);
      const local = localEvents.get(node.node_id) ?? 0;
      const onPath = pathHosts.has(node.node_id);
      const note = switches.get(node.node_id);
      return {
        id: node.node_id, width: placed.width, height: placed.height,
        position: { x: placed.x - placed.width / 2, y: placed.y - placed.height / 2 },
        data: {
          node, localEvents: local, onPath, dimmed: path !== null && !onPath,
          selected: options.selection?.kind === "node" && options.selection.id === node.node_id,
          switchNote: note === undefined ? null : note ? "weak" : "conditional",
        },
      };
    }),
    edges: links.map((link) => ({
      id: link.link_id, source: link.source, target: link.target,
      data: {
        link, state: edgeState(link, path),
        selected: options.selection?.kind === "link" && options.selection.id === link.link_id,
      },
    })),
  };
}
