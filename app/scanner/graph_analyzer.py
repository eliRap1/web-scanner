"""
DFS Graph Analyzer for Vulnerability Clusters

Builds a directed graph where:
- Nodes = pages/URLs discovered during crawling
- Edges = links between pages (directional)
- Each node stores associated vulnerabilities

Key features:
1. DFS-based cycle detection using WHITE/GRAY/BLACK coloring
2. Vulnerability cluster identification (connected components sharing vuln types)
3. Connected component computation
4. JSON-serializable diagram data generation for frontend visualization
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class NodeColor(Enum):
    WHITE = "white"   # Unvisited
    GRAY = "gray"     # Currently being explored (on the DFS stack)
    BLACK = "black"   # Fully explored


@dataclass
class GraphNode:
    """Represents a single page/URL in the vulnerability graph."""
    url: str
    depth: int = 0
    parent_url: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    outgoing_edges: Set[str] = field(default_factory=set)
    discovery_time: int = -1
    finish_time: int = -1


@dataclass
class CycleInfo:
    """Represents a detected cycle in the directed page graph."""
    cycle_urls: List[str]
    back_edge: Tuple[str, str]
    shared_vuln_types: List[str]
    length: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle_urls": self.cycle_urls,
            "back_edge": {"from": self.back_edge[0], "to": self.back_edge[1]},
            "shared_vuln_types": self.shared_vuln_types,
            "length": self.length,
        }


@dataclass
class VulnerabilityCluster:
    """A group of connected pages sharing the same vulnerability type."""
    cluster_id: int
    vuln_type: str
    urls: List[str]
    total_findings: int
    severity_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "vuln_type": self.vuln_type,
            "urls": self.urls,
            "total_findings": self.total_findings,
            "severity_breakdown": self.severity_breakdown,
        }


class VulnerabilityGraph:
    """
    Directed graph of web pages and their vulnerabilities.

    Supports:
    * DFS-based cycle detection (WHITE/GRAY/BLACK colouring)
    * Connected-component computation (undirected view)
    * Vulnerability-cluster identification (connected pages sharing a vuln type)
    * JSON-serializable diagram-data export (for the React frontend)
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self._time_counter: int = 0
        self._color: Dict[str, NodeColor] = {}
        self._parent_map: Dict[str, Optional[str]] = {}
        self._cycles: List[CycleInfo] = []
        self._back_edges: List[Tuple[str, str]] = []

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_node(self, url: str, depth: int = 0, parent_url: Optional[str] = None) -> GraphNode:
        if url not in self.nodes:
            self.nodes[url] = GraphNode(url=url, depth=depth, parent_url=parent_url)
        else:
            if depth < self.nodes[url].depth:
                self.nodes[url].depth = depth
            if parent_url and not self.nodes[url].parent_url:
                self.nodes[url].parent_url = parent_url
        return self.nodes[url]

    def add_edge(self, from_url: str, to_url: str):
        if from_url in self.nodes:
            self.nodes[from_url].outgoing_edges.add(to_url)
        if to_url not in self.nodes:
            self.add_node(to_url)

    def add_vulnerability(self, url: str, vulnerability: Dict[str, Any]):
        if url not in self.nodes:
            self.add_node(url)
        self.nodes[url].vulnerabilities.append(vulnerability)

    def get_nodes(self) -> List[Dict[str, Any]]:
        return [
            {"url": n.url, "depth": n.depth, "vulnerabilities": n.vulnerabilities}
            for n in self.nodes.values()
        ]

    def get_edges(self) -> List[Dict[str, str]]:
        edges = []
        for url, node in self.nodes.items():
            for target in node.outgoing_edges:
                if target in self.nodes:
                    edges.append({"source": url, "target": target})
        return edges

    def build_from_crawl_data(
        self,
        visited_urls: List[str],
        page_links: Dict[str, Set[str]],
        page_depths: Dict[str, int],
        page_parents: Dict[str, Optional[str]],
        findings: List[Dict[str, Any]],
    ):
        for url in visited_urls:
            self.add_node(
                url=url,
                depth=page_depths.get(url, 0),
                parent_url=page_parents.get(url),
            )
        for from_url, links in page_links.items():
            for to_url in links:
                self.add_edge(from_url, to_url)
        for finding in findings:
            vuln_url = finding.get("url", "")
            if vuln_url:
                self.add_vulnerability(vuln_url, finding)

        logger.info(
            "Graph built: %d nodes, %d edges",
            len(self.nodes),
            sum(len(n.outgoing_edges) for n in self.nodes.values()),
        )

    # ------------------------------------------------------------------
    # DFS cycle detection (WHITE/GRAY/BLACK)
    # ------------------------------------------------------------------

    def detect_cycles(self) -> Dict[str, Any]:
        """
        Run DFS to find directed cycles.

        Returns dict with:
            has_cycles: bool
            cycles: list of cycle paths (each a list of URLs)
        """
        self._time_counter = 0
        self._color = {url: NodeColor.WHITE for url in self.nodes}
        self._parent_map = {url: None for url in self.nodes}
        self._cycles = []
        self._back_edges = []

        for url in self.nodes:
            if self._color[url] == NodeColor.WHITE:
                self._dfs_visit(url)

        logger.info("Cycle detection complete: %d cycles found", len(self._cycles))
        return {
            "has_cycles": len(self._cycles) > 0,
            "cycles": [c.cycle_urls for c in self._cycles],
            "cycle_details": [c.to_dict() for c in self._cycles],
        }

    def _dfs_visit(self, url: str):
        self._time_counter += 1
        self.nodes[url].discovery_time = self._time_counter
        self._color[url] = NodeColor.GRAY

        for neighbor in self.nodes[url].outgoing_edges:
            if neighbor not in self.nodes:
                continue
            if self._color[neighbor] == NodeColor.WHITE:
                self._parent_map[neighbor] = url
                self._dfs_visit(neighbor)
            elif self._color[neighbor] == NodeColor.GRAY:
                self._back_edges.append((url, neighbor))
                cycle = self._reconstruct_cycle(url, neighbor)
                self._cycles.append(cycle)

        self._color[url] = NodeColor.BLACK
        self._time_counter += 1
        self.nodes[url].finish_time = self._time_counter

    def _reconstruct_cycle(self, from_url: str, to_url: str) -> CycleInfo:
        path = [from_url]
        current = from_url
        while current != to_url:
            current = self._parent_map.get(current)
            if current is None:
                break
            path.append(current)
        path.reverse()

        vuln_type_sets: List[Set[str]] = []
        for url in path:
            node = self.nodes.get(url)
            if node and node.vulnerabilities:
                types: Set[str] = set()
                for v in node.vulnerabilities:
                    vtype = v.get("type") or v.get("vuln_type", "")
                    if vtype:
                        types.add(vtype)
                vuln_type_sets.append(types)

        shared: Set[str] = set()
        non_empty = [s for s in vuln_type_sets if s]
        if non_empty:
            shared = non_empty[0].copy()
            for s in non_empty[1:]:
                shared &= s

        return CycleInfo(
            cycle_urls=path,
            back_edge=(from_url, to_url),
            shared_vuln_types=sorted(shared),
            length=len(path),
        )

    # ------------------------------------------------------------------
    # Connected components (undirected view)
    # ------------------------------------------------------------------

    def compute_connected_components(self) -> List[List[str]]:
        undirected: Dict[str, Set[str]] = {url: set() for url in self.nodes}
        for url, node in self.nodes.items():
            for neighbor in node.outgoing_edges:
                if neighbor in self.nodes:
                    undirected[url].add(neighbor)
                    undirected[neighbor].add(url)

        visited: Set[str] = set()
        components: List[List[str]] = []
        for url in self.nodes:
            if url in visited:
                continue
            component: List[str] = []
            stack = [url]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                for nb in undirected[current]:
                    if nb not in visited:
                        stack.append(nb)
            components.append(component)
        return components

    # ------------------------------------------------------------------
    # Vulnerability cluster analysis
    # ------------------------------------------------------------------

    def find_vulnerability_clusters(self) -> List[Dict[str, Any]]:
        """Group connected pages sharing the same vulnerability type."""
        components = self.compute_connected_components()
        clusters: List[Dict[str, Any]] = []
        cluster_id = 0

        for component in components:
            vuln_type_to_urls: Dict[str, List[str]] = {}
            vuln_type_to_findings: Dict[str, List[Dict[str, Any]]] = {}

            for url in component:
                node = self.nodes.get(url)
                if not node or not node.vulnerabilities:
                    continue
                for vuln in node.vulnerabilities:
                    vtype = vuln.get("type") or vuln.get("vuln_type", "Unknown")
                    if vtype not in vuln_type_to_urls:
                        vuln_type_to_urls[vtype] = []
                        vuln_type_to_findings[vtype] = []
                    if url not in vuln_type_to_urls[vtype]:
                        vuln_type_to_urls[vtype].append(url)
                    vuln_type_to_findings[vtype].append(vuln)

            for vtype, urls in vuln_type_to_urls.items():
                findings = vuln_type_to_findings[vtype]
                severity_counts: Dict[str, int] = {}
                for f in findings:
                    sev = (f.get("severity") or "medium").lower()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                clusters.append({
                    "cluster_id": cluster_id,
                    "vuln_type": vtype,
                    "urls": urls,
                    "total_findings": len(findings),
                    "severity_breakdown": severity_counts,
                })
                cluster_id += 1

        return clusters

    # ------------------------------------------------------------------
    # Diagram data (JSON-serializable export for frontend)
    # ------------------------------------------------------------------

    def generate_diagram_data(self) -> Dict[str, Any]:
        """Return JSON-serializable dict for the React frontend."""
        cycles_result = self.detect_cycles()
        clusters = self.find_vulnerability_clusters()
        components = self.compute_connected_components()

        # Severity priority for determining worst
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        # Build nodes
        node_list: List[Dict[str, Any]] = []
        for url, node in self.nodes.items():
            vuln_types: Set[str] = set()
            worst_severity = "none"
            worst_score = 0
            for v in node.vulnerabilities:
                vt = v.get("type") or v.get("vuln_type", "")
                if vt:
                    vuln_types.add(vt)
                sv = (v.get("severity") or "").lower()
                score = severity_order.get(sv, 0)
                if score > worst_score:
                    worst_score = score
                    worst_severity = sv

            node_list.append({
                "id": url,
                "url": url,
                "depth": node.depth,
                "parent_url": node.parent_url,
                "vulnerabilities": node.vulnerabilities,
                "vulnerability_count": len(node.vulnerabilities),
                "vulnerability_types": sorted(vuln_types),
                "severity": worst_severity if node.vulnerabilities else "none",
                "discovery_time": node.discovery_time,
                "finish_time": node.finish_time,
            })

        # Build edges with cycle marking
        back_edge_set = set(self._back_edges)
        edge_list: List[Dict[str, Any]] = []
        for url, node in self.nodes.items():
            for target in node.outgoing_edges:
                if target in self.nodes:
                    edge_list.append({
                        "source": url,
                        "target": target,
                        "is_cycle_edge": (url, target) in back_edge_set,
                    })

        # Component map
        component_map: Dict[str, int] = {}
        for idx, comp in enumerate(components):
            for u in comp:
                component_map[u] = idx

        # Summary stats
        total_vulns = sum(len(n.vulnerabilities) for n in self.nodes.values())
        all_vuln_types: Set[str] = set()
        for n in self.nodes.values():
            for v in n.vulnerabilities:
                vt = v.get("type") or v.get("vuln_type", "")
                if vt:
                    all_vuln_types.add(vt)

        return {
            "nodes": node_list,
            "edges": edge_list,
            "cycles": cycles_result.get("cycle_details", []),
            "clusters": clusters,
            "components": [
                {"component_id": idx, "urls": comp}
                for idx, comp in enumerate(components)
            ],
            "component_map": component_map,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(edge_list),
                "total_vulnerabilities": total_vulns,
                "total_cycles": len(self._cycles),
                "total_clusters": len(clusters),
                "total_components": len(components),
                "unique_vulnerability_types": sorted(all_vuln_types),
            },
        }

    def __repr__(self) -> str:
        edge_count = sum(len(n.outgoing_edges) for n in self.nodes.values())
        return f"VulnerabilityGraph(nodes={len(self.nodes)}, edges={edge_count})"
