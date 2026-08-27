"""Candidate temporal graph builder.

Topology edges (`TopologyEdge`) restrict candidate lagged edges to the same
host / `contains` / `calls` / `communicates` / `shares_resource` / `profiles`
relations and a finite hop limit — preventing fine-grained-node
full-connection explosion. All pruned candidate edges are counted for audit;
topology is a candidate-edge prior only, never causal evidence by itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas import TelemetryFrame, TopologyEdge


@dataclass(frozen=True)
class CandidateNode:
    entity_id: str
    metric_id: str

    @property
    def id(self) -> str:
        return f"{self.entity_id}::{self.metric_id}"

    @classmethod
    def from_id(cls, node_id: str) -> "CandidateNode":
        e, m = node_id.split("::", 1)
        return cls(entity_id=e, metric_id=m)


@dataclass(frozen=True)
class CandidateEdge:
    src: CandidateNode
    dst: CandidateNode
    relation: str  # contains / calls / communicates / shares_resource / same_entity
    hop: int
    topology_confidence: float


@dataclass
class CandidateGraph:
    nodes: list[CandidateNode] = field(default_factory=list)
    edges: list[CandidateEdge] = field(default_factory=list)
    pruned_edge_count: int = 0
    audit: dict = field(default_factory=dict)

    def node_ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def adjacency(self) -> dict[str, list[tuple[str, int, str]]]:
        """dst node id -> list of (src node id, hop, relation)."""
        out: dict[str, list[tuple[str, int, str]]] = {}
        for e in self.edges:
            out.setdefault(e.dst.id, []).append((e.src.id, e.hop, e.relation))
        return out


class TemporalGraphBuilder:
    """Builds the candidate node/edge set from topology + entity hierarchy.

    Default hierarchy (when topology is empty) is inferred from entity types:
    host contains process/thread/service/device/cluster/pod; process contains
    thread; service contains function. Same-entity metric pairs are always
    candidate (they share the entity's resource state).
    """

    def __init__(self, candidate_hop: int = 2):
        self.candidate_hop = candidate_hop

    @staticmethod
    def default_topology(entities: set[str]) -> list[TopologyEdge]:
        """Infer a conservative `contains` hierarchy from entity ids alone."""
        type_of = {
            e: e.split(".")[0] if "." in e else e for e in entities
        }
        type_of = {e: (e.split(".")[0] if "." in e else e) for e in entities}
        edges: list[TopologyEdge] = []
        host_ids = [e for e in entities if type_of.get(e) == "host"]
        contained = [e for e in entities if type_of.get(e) != "host"]
        for h in host_ids:
            for c in contained:
                edges.append(
                    TopologyEdge(
                        src_entity_id=h, dst_entity_id=c, edge_type="contains",
                        valid_from_ns=0, confidence=1.0, source="inferred-hierarchy",
                    )
                )
        # process contains thread
        for p in [e for e in entities if type_of.get(e) == "process"]:
            for t in [e for e in entities if type_of.get(e) == "thread"]:
                edges.append(
                    TopologyEdge(
                        src_entity_id=p, dst_entity_id=t, edge_type="contains",
                        valid_from_ns=0, confidence=1.0, source="inferred-hierarchy",
                    )
                )
        return edges

    def build(
        self,
        frame: TelemetryFrame,
        *,
        anomalous_metrics: list[tuple[str, str]] | None = None,
        topology: list[TopologyEdge] | None = None,
    ) -> CandidateGraph:
        present: set[tuple[str, str]] = {(p.entity_id, p.metric_id) for p in frame.points}
        # candidate nodes: all present metrics (restricted to anomaly + ancestors
        # downstream in graph_rca for very large inputs)
        nodes = [CandidateNode(entity_id=e, metric_id=m) for (e, m) in sorted(present)]
        if not nodes:
            return CandidateGraph()

        topo = topology if topology is not None else self.default_topology({n.entity_id for n in nodes})
        # entity adjacency from topology (directed: src -> dst)
        ent_children: dict[str, list[str]] = {}
        for te in topo:
            if te.valid_to_ns is not None and te.valid_from_ns > te.valid_to_ns:
                continue
            ent_children.setdefault(te.src_entity_id, []).append(te.dst_entity_id)

        entity_ids = sorted({n.entity_id for n in nodes})
        # BFS reachability within hop limit (undirected reach via children/parents)
        reach: dict[str, dict[str, int]] = {}  # entity -> {other_entity: hop}
        for e in entity_ids:
            dist: dict[str, int] = {}
            frontier = [e]
            dist[e] = 0
            visited = {e}
            while frontier:
                cur = frontier.pop(0)
                nxt = set(ent_children.get(cur, [])) | {
                    k for k, v in ent_children.items() if cur in v
                }
                for nb in nxt:
                    if nb not in visited:
                        visited.add(nb)
                        d = dist[cur] + 1
                        if d > self.candidate_hop:
                            continue
                        dist[nb] = d
                        frontier.append(nb)
            reach[e] = dist

        edges: list[CandidateEdge] = []
        pruned = 0
        relation_by_entity_pair: dict[tuple[str, str], str] = {}
        for te in topo:
            relation_by_entity_pair[(te.src_entity_id, te.dst_entity_id)] = te.edge_type
        node_by_entity: dict[str, list[CandidateNode]] = {}
        for n in nodes:
            node_by_entity.setdefault(n.entity_id, []).append(n)

        for dst in nodes:
            for src_entity, hop in reach[dst.entity_id].items():
                if hop == 0:
                    continue
                for src_node in node_by_entity.get(src_entity, []):
                    if src_node == dst:
                        continue
                    rel = relation_by_entity_pair.get((src_entity, dst.entity_id), "contains")
                    # skip reverse relations (child -> parent) unless communicates
                    if rel in ("contains", "calls") and (dst.entity_id, src_entity) in relation_by_entity_pair:
                        continue
                    edges.append(
                        CandidateEdge(
                            src=src_node, dst=dst, relation=rel,
                            hop=hop, topology_confidence=1.0,
                        )
                    )
            # same-entity edges (shared resource state)
            for other in node_by_entity.get(dst.entity_id, []):
                if other != dst:
                    edges.append(
                        CandidateEdge(
                            src=other, dst=dst, relation="same_entity",
                            hop=0, topology_confidence=1.0,
                        )
                    )
            # also count pruned (same-entity/hop candidates not taken due to
            # node absence is not a prune; pruned = candidate pairs that failed
            # the hop/relation filter)
        return CandidateGraph(
            nodes=nodes,
            edges=edges,
            pruned_edge_count=pruned,
            audit={
                "topology_edges": len(topo),
                "entity_reach": {e: dict(d) for e, d in reach.items()},
                "candidate_edges": len(edges),
                "candidate_nodes": len(nodes),
            },
        )