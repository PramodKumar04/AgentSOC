import { describe, expect, it } from "vitest";

import { buildFlow, type FlowOptions } from "@/components/graph/graph-model";
import type { IncidentGraph } from "@/lib/api";
import { AMBIGUOUS, GRAPH, INFERRED, OBSERVED } from "./dashboard-fixtures";

const ALL: FlowOptions = { showAccounts: true, showAttempts: true, pathId: null, selection: null };
const flow = (options: Partial<FlowOptions> = {}, graph: IncidentGraph = GRAPH) => buildFlow(graph, { ...ALL, ...options });
const state = (f: ReturnType<typeof flow>, id: string) => f.edges.find((e) => e.id === id)!.data.state;

describe("attack graph model", () => {
  it("draws exactly the server's links, unchanged", () => {
    const { edges } = flow();
    const links = new Map(GRAPH.links.map((k) => [k.link_id, k]));
    expect(edges.length).toBeGreaterThan(0);
    for (const e of edges) {
      const link = links.get(e.id)!;
      expect(link).toBeDefined();
      expect([e.source, e.target]).toEqual([link.source, link.target]);
      expect(e.data.link).toBe(link);
    }
  });

  it("adds no edge for an inferred path", () => {
    const plain = flow().edges.map((e) => e.id);
    expect(flow({ pathId: INFERRED.path_id }).edges.map((e) => e.id)).toEqual(plain);
  });

  it("shows a local logon on its host instead of as an edge", () => {
    const f = flow();
    expect(f.edges.some((e) => e.data.link.kind === "LOCAL")).toBe(false);
    expect(f.nodes.find((n) => n.id === "host:WS1")!.data.localEvents).toBe(1);
  });

  it("can hide account nodes and failed attempts", () => {
    const f = flow({ showAccounts: false, showAttempts: false });
    expect(f.nodes.every((n) => n.data.node.kind === "host")).toBe(true);
    expect(f.edges.every((e) => e.data.link.kind === "MOVEMENT")).toBe(true);
  });

  it("highlights only links the path lists", () => {
    const f = flow({ pathId: OBSERVED.path_id });
    for (const id of OBSERVED.link_ids) expect(state(f, id)).toBe("path-observed");
    expect(state(f, "MOVEMENT|host:SRV1|host:APP1")).toBe("dimmed");
  });

  it("distinguishes observed, inferred and weak paths", () => {
    const id = "MOVEMENT|host:WS1|host:SRV1";
    expect(state(flow({ pathId: OBSERVED.path_id }), id)).toBe("path-observed");
    expect(state(flow({ pathId: INFERRED.path_id }), id)).toBe("path-inferred");
    expect(state(flow({ pathId: AMBIGUOUS.path_id }), id)).toBe("path-ambiguous");
  });

  it("never places a failed attempt on a path", () => {
    for (const path of GRAPH.paths) {
      expect(state(flow({ pathId: path.path_id }), "ATTEMPT|host:WS1|host:SRV1")).toBe("dimmed");
    }
  });

  it("marks the account switch host, and how strong the link is", () => {
    const at = (pathId: string) => flow({ pathId }).nodes.find((n) => n.id === "host:SRV1")!.data.switchNote;
    expect(at(OBSERVED.path_id)).toBeNull();
    expect(at(INFERRED.path_id)).toBe("conditional");
    expect(at(AMBIGUOUS.path_id)).toBe("weak");
  });

  it("keeps the accounts on a selected path visible", () => {
    const { nodes } = flow({ pathId: OBSERVED.path_id });
    expect(nodes.find((n) => n.id === `user:${OBSERVED.accounts[0]}`)!.data.dimmed).toBe(false);
    expect(nodes.find((n) => n.id === "user:bob.it@CORP")!.data.dimmed).toBe(true);
  });

  it("ignores an unknown path rather than guessing", () => {
    expect(flow({ pathId: "P-NOPE" }).edges.every((e) => e.data.state === "default")).toBe(true);
  });

  it("lays out cycles without overlapping nodes", () => {
    const hosts = ["A", "B", "C", "D", "E", "F"];
    const cyclic: IncidentGraph = {
      ...GRAPH, paths: [],
      nodes: hosts.map((h) => ({ node_id: `host:${h}`, kind: "host", label: h, roles: [], event_count: 1 })),
      links: hosts.map((h, i) => ({ ...GRAPH.links[0], kind: "MOVEMENT", link_id: `L${i}`, source: `host:${h}`, target: `host:${hosts[(i + 1) % 6]}` })),
    };
    const { nodes } = flow({}, cyclic);
    expect(nodes.every((n) => Number.isFinite(n.position.x) && Number.isFinite(n.position.y))).toBe(true);
    for (const a of nodes) {
      for (const b of nodes) {
        if (a === b) continue;
        const apart = a.position.x + a.width <= b.position.x || b.position.x + b.width <= a.position.x
          || a.position.y + a.height <= b.position.y || b.position.y + b.height <= a.position.y;
        expect(apart).toBe(true);
      }
    }
  });
});
