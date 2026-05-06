"""
Unit tests for the DFS Graph Analysis feature (app/scanner/graph_analyzer.py).

These tests cover:
- Graph construction (adding nodes, edges, vulnerabilities)
- DFS cycle detection (simple cycles, self-loops, complex/disconnected graphs)
- Vulnerability clustering (grouping pages by shared vuln types)
- Diagram data generation (JSON-serializable output)
- Integration-style full-workflow tests

The tests are designed against the expected API described in the feature spec.
They will pass once graph_analyzer.py is implemented with:
  - VulnerabilityGraph class
  - add_node(url, depth=0), add_edge(source, target), detect_cycles(),
    find_vulnerability_clusters(), generate_diagram_data()
  - Graph nodes carry: url, depth, vulnerabilities list, outgoing edges
  - DFS uses WHITE/GRAY/BLACK coloring for cycle detection
"""

import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import pytest

from scanner.graph_analyzer import VulnerabilityGraph


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def empty_graph():
    """Return a fresh, empty VulnerabilityGraph."""
    return VulnerabilityGraph()


@pytest.fixture()
def simple_linear_graph():
    """A -> B -> C  (no cycle)."""
    g = VulnerabilityGraph()
    g.add_node("http://example.com/a", depth=0)
    g.add_node("http://example.com/b", depth=1)
    g.add_node("http://example.com/c", depth=2)
    g.add_edge("http://example.com/a", "http://example.com/b")
    g.add_edge("http://example.com/b", "http://example.com/c")
    return g


@pytest.fixture()
def simple_cycle_graph():
    """A -> B -> C -> A  (one cycle)."""
    g = VulnerabilityGraph()
    for url, d in [
        ("http://example.com/a", 0),
        ("http://example.com/b", 1),
        ("http://example.com/c", 2),
    ]:
        g.add_node(url, depth=d)
    g.add_edge("http://example.com/a", "http://example.com/b")
    g.add_edge("http://example.com/b", "http://example.com/c")
    g.add_edge("http://example.com/c", "http://example.com/a")
    return g


@pytest.fixture()
def self_loop_graph():
    """A -> A  (self-loop)."""
    g = VulnerabilityGraph()
    g.add_node("http://example.com/a", depth=0)
    g.add_edge("http://example.com/a", "http://example.com/a")
    return g


@pytest.fixture()
def complex_multi_cycle_graph():
    """
    Graph with two independent cycles and a linear component:

        A -> B -> C -> A          (cycle 1)
        C -> D -> E -> C          (cycle 2, shares node C)
        F -> G                    (linear, no cycle)
    """
    g = VulnerabilityGraph()
    for url, d in [
        ("http://example.com/a", 0),
        ("http://example.com/b", 1),
        ("http://example.com/c", 2),
        ("http://example.com/d", 3),
        ("http://example.com/e", 4),
        ("http://example.com/f", 0),
        ("http://example.com/g", 1),
    ]:
        g.add_node(url, depth=d)

    # cycle 1
    g.add_edge("http://example.com/a", "http://example.com/b")
    g.add_edge("http://example.com/b", "http://example.com/c")
    g.add_edge("http://example.com/c", "http://example.com/a")
    # cycle 2
    g.add_edge("http://example.com/c", "http://example.com/d")
    g.add_edge("http://example.com/d", "http://example.com/e")
    g.add_edge("http://example.com/e", "http://example.com/c")
    # linear
    g.add_edge("http://example.com/f", "http://example.com/g")
    return g


@pytest.fixture()
def graph_with_vulns():
    """Graph where nodes carry vulnerability data for cluster testing."""
    g = VulnerabilityGraph()
    g.add_node("http://example.com/login", depth=0)
    g.add_node("http://example.com/search", depth=1)
    g.add_node("http://example.com/profile", depth=1)
    g.add_node("http://example.com/admin", depth=2)
    g.add_node("http://example.com/static", depth=1)

    g.add_edge("http://example.com/login", "http://example.com/search")
    g.add_edge("http://example.com/login", "http://example.com/profile")
    g.add_edge("http://example.com/profile", "http://example.com/admin")
    g.add_edge("http://example.com/login", "http://example.com/static")

    # Add vulnerabilities to specific nodes
    g.add_vulnerability("http://example.com/login", {
        "type": "SQLi",
        "severity": "critical",
        "parameter": "username",
    })
    g.add_vulnerability("http://example.com/search", {
        "type": "XSS",
        "severity": "high",
        "parameter": "q",
    })
    g.add_vulnerability("http://example.com/search", {
        "type": "SQLi",
        "severity": "critical",
        "parameter": "q",
    })
    g.add_vulnerability("http://example.com/profile", {
        "type": "XSS",
        "severity": "high",
        "parameter": "bio",
    })
    g.add_vulnerability("http://example.com/admin", {
        "type": "SQLi",
        "severity": "critical",
        "parameter": "id",
    })
    # /static has no vulnerabilities
    return g


# ===================================================================
# a) Graph Construction Tests
# ===================================================================

class TestGraphConstruction:
    """Tests for adding nodes, edges, and vulnerabilities."""

    def test_add_single_node(self, empty_graph):
        """Adding a node should make it retrievable in the graph."""
        empty_graph.add_node("http://example.com", depth=0)
        nodes = empty_graph.get_nodes()
        assert len(nodes) == 1
        node = nodes[0]
        assert node["url"] == "http://example.com"
        assert node["depth"] == 0

    def test_add_multiple_nodes(self, empty_graph):
        """Adding multiple distinct nodes increases the count."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_node("http://example.com/b", depth=1)
        empty_graph.add_node("http://example.com/c", depth=2)
        assert len(empty_graph.get_nodes()) == 3

    def test_add_duplicate_node_ignored(self, empty_graph):
        """Adding a node with the same URL twice should not create duplicates."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_node("http://example.com/a", depth=0)
        assert len(empty_graph.get_nodes()) == 1

    def test_add_edge_between_existing_nodes(self, empty_graph):
        """Edges between existing nodes should be stored correctly."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_node("http://example.com/b", depth=1)
        empty_graph.add_edge("http://example.com/a", "http://example.com/b")
        edges = empty_graph.get_edges()
        assert len(edges) == 1
        assert edges[0]["source"] == "http://example.com/a"
        assert edges[0]["target"] == "http://example.com/b"

    def test_add_edge_nonexistent_source_no_edge_stored(self, empty_graph):
        """An edge from a non-existent source is silently ignored (source side)."""
        empty_graph.add_node("http://example.com/b", depth=1)
        empty_graph.add_edge("http://nonexist.com", "http://example.com/b")
        # Source didn't exist so the outgoing edge wasn't recorded
        edges = empty_graph.get_edges()
        assert len(edges) == 0

    def test_add_edge_nonexistent_target_auto_creates(self, empty_graph):
        """An edge to a non-existent target auto-creates the target node."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_edge("http://example.com/a", "http://nonexist.com")
        assert len(empty_graph.get_nodes()) == 2
        edges = empty_graph.get_edges()
        assert len(edges) == 1

    def test_add_edge_both_nonexistent_no_edge(self, empty_graph):
        """An edge where source doesn't exist stores no outgoing edge."""
        empty_graph.add_edge("http://no.com/x", "http://no.com/y")
        # target auto-created but source had no outgoing edge stored
        edges = empty_graph.get_edges()
        assert len(edges) == 0

    def test_add_vulnerability_to_node(self, empty_graph):
        """Vulnerabilities can be attached to existing nodes."""
        empty_graph.add_node("http://example.com/a", depth=0)
        vuln = {"type": "SQLi", "severity": "critical", "parameter": "id"}
        empty_graph.add_vulnerability("http://example.com/a", vuln)
        nodes = empty_graph.get_nodes()
        assert len(nodes[0]["vulnerabilities"]) == 1
        assert nodes[0]["vulnerabilities"][0]["type"] == "SQLi"

    def test_add_multiple_vulnerabilities_to_one_node(self, empty_graph):
        """A single node can hold several vulnerabilities."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_vulnerability("http://example.com/a", {
            "type": "SQLi", "severity": "critical", "parameter": "id"
        })
        empty_graph.add_vulnerability("http://example.com/a", {
            "type": "XSS", "severity": "high", "parameter": "name"
        })
        nodes = empty_graph.get_nodes()
        assert len(nodes[0]["vulnerabilities"]) == 2

    def test_node_defaults_to_empty_vulnerabilities(self, empty_graph):
        """Newly added nodes start with an empty vulnerability list."""
        empty_graph.add_node("http://example.com/a", depth=0)
        nodes = empty_graph.get_nodes()
        assert nodes[0]["vulnerabilities"] == []

    def test_node_stores_depth(self, empty_graph):
        """Depth should be correctly stored on the node."""
        empty_graph.add_node("http://example.com/deep", depth=5)
        nodes = empty_graph.get_nodes()
        assert nodes[0]["depth"] == 5

    def test_get_edges_returns_list(self, simple_linear_graph):
        """get_edges should return a list of edge dicts."""
        edges = simple_linear_graph.get_edges()
        assert isinstance(edges, list)
        assert len(edges) == 2

    def test_get_nodes_returns_list(self, simple_linear_graph):
        """get_nodes should return a list of node dicts."""
        nodes = simple_linear_graph.get_nodes()
        assert isinstance(nodes, list)
        assert len(nodes) == 3


# ===================================================================
# b) DFS Cycle Detection Tests
# ===================================================================

class TestDFSCycleDetection:
    """Tests for detect_cycles() using WHITE/GRAY/BLACK DFS coloring."""

    def test_simple_cycle_detected(self, simple_cycle_graph):
        """A -> B -> C -> A should report at least one cycle."""
        result = simple_cycle_graph.detect_cycles()
        assert result["has_cycles"] is True
        assert len(result["cycles"]) >= 1

    def test_no_cycle_in_linear_graph(self, simple_linear_graph):
        """A -> B -> C (no back edge) should report no cycles."""
        result = simple_linear_graph.detect_cycles()
        assert result["has_cycles"] is False
        assert len(result["cycles"]) == 0

    def test_self_loop_detected(self, self_loop_graph):
        """A -> A should be detected as a cycle."""
        result = self_loop_graph.detect_cycles()
        assert result["has_cycles"] is True
        assert len(result["cycles"]) >= 1

    def test_multiple_cycles_detected(self, complex_multi_cycle_graph):
        """Graph with two overlapping cycles should find multiple cycles."""
        result = complex_multi_cycle_graph.detect_cycles()
        assert result["has_cycles"] is True
        assert len(result["cycles"]) >= 2

    def test_disconnected_components_partial_cycles(self, complex_multi_cycle_graph):
        """
        The linear component (F->G) has no cycle while the main
        component has cycles.  detect_cycles should still find cycles
        and the linear component nodes should not appear in any cycle path.
        """
        result = complex_multi_cycle_graph.detect_cycles()
        assert result["has_cycles"] is True
        all_cycle_urls = set()
        for cycle in result["cycles"]:
            all_cycle_urls.update(cycle)
        assert "http://example.com/f" not in all_cycle_urls
        assert "http://example.com/g" not in all_cycle_urls

    def test_cycle_paths_are_reported_correctly(self, simple_cycle_graph):
        """The reported cycle path should form a valid cycle in the graph."""
        result = simple_cycle_graph.detect_cycles()
        assert len(result["cycles"]) >= 1
        cycle = result["cycles"][0]
        assert isinstance(cycle, list)
        assert len(cycle) >= 2

    def test_empty_graph_no_cycles(self, empty_graph):
        """An empty graph should have no cycles."""
        result = empty_graph.detect_cycles()
        assert result["has_cycles"] is False
        assert result["cycles"] == []

    def test_single_node_no_edges_no_cycles(self, empty_graph):
        """A single node with no edges has no cycle."""
        empty_graph.add_node("http://example.com/alone", depth=0)
        result = empty_graph.detect_cycles()
        assert result["has_cycles"] is False

    def test_two_node_cycle(self, empty_graph):
        """A -> B -> A (two-node cycle) should be detected."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_node("http://example.com/b", depth=1)
        empty_graph.add_edge("http://example.com/a", "http://example.com/b")
        empty_graph.add_edge("http://example.com/b", "http://example.com/a")
        result = empty_graph.detect_cycles()
        assert result["has_cycles"] is True

    def test_large_graph_performance(self, empty_graph):
        """
        Cycle detection on a graph with 150 nodes and many edges
        should complete in a reasonable time (< 2 seconds).
        """
        n = 150
        urls = [f"http://example.com/page{i}" for i in range(n)]

        for i, url in enumerate(urls):
            empty_graph.add_node(url, depth=i % 10)

        for i in range(n - 1):
            empty_graph.add_edge(urls[i], urls[i + 1])
        for i in range(0, n, 10):
            target_idx = max(0, i - 5)
            empty_graph.add_edge(urls[min(i + 9, n - 1)], urls[target_idx])

        start = time.time()
        result = empty_graph.detect_cycles()
        elapsed = time.time() - start

        assert result["has_cycles"] is True
        assert elapsed < 2.0, f"Cycle detection took {elapsed:.2f}s on {n}-node graph"

    def test_dag_no_cycles(self, empty_graph):
        """A directed acyclic graph (diamond shape) should have no cycles."""
        for url, d in [
            ("http://example.com/a", 0),
            ("http://example.com/b", 1),
            ("http://example.com/c", 1),
            ("http://example.com/d", 2),
        ]:
            empty_graph.add_node(url, depth=d)
        empty_graph.add_edge("http://example.com/a", "http://example.com/b")
        empty_graph.add_edge("http://example.com/a", "http://example.com/c")
        empty_graph.add_edge("http://example.com/b", "http://example.com/d")
        empty_graph.add_edge("http://example.com/c", "http://example.com/d")

        result = empty_graph.detect_cycles()
        assert result["has_cycles"] is False

    def test_detect_cycles_returns_dict(self, simple_linear_graph):
        """detect_cycles() must return a dict with has_cycles and cycles keys."""
        result = simple_linear_graph.detect_cycles()
        assert isinstance(result, dict)
        assert "has_cycles" in result
        assert "cycles" in result
        assert isinstance(result["has_cycles"], bool)
        assert isinstance(result["cycles"], list)

    def test_cycle_in_fully_connected_three_nodes(self, empty_graph):
        """A fully connected 3-node graph has cycles."""
        urls = [
            "http://example.com/a",
            "http://example.com/b",
            "http://example.com/c",
        ]
        for url in urls:
            empty_graph.add_node(url, depth=0)
        for i in range(3):
            for j in range(3):
                if i != j:
                    empty_graph.add_edge(urls[i], urls[j])
        result = empty_graph.detect_cycles()
        assert result["has_cycles"] is True


# ===================================================================
# c) Vulnerability Cluster Tests
# ===================================================================

class TestVulnerabilityClusters:
    """Tests for find_vulnerability_clusters()."""

    def test_sqli_cluster(self, graph_with_vulns):
        """Nodes with SQLi should form one cluster."""
        clusters = graph_with_vulns.find_vulnerability_clusters()
        sqli_cluster = None
        for cluster in clusters:
            if cluster["vuln_type"] == "SQLi":
                sqli_cluster = cluster
                break

        assert sqli_cluster is not None, "Expected an SQLi cluster"
        sqli_urls = set(sqli_cluster["urls"])
        assert "http://example.com/login" in sqli_urls
        assert "http://example.com/search" in sqli_urls
        assert "http://example.com/admin" in sqli_urls

    def test_xss_cluster(self, graph_with_vulns):
        """Nodes with XSS should form another cluster."""
        clusters = graph_with_vulns.find_vulnerability_clusters()
        xss_cluster = None
        for cluster in clusters:
            if cluster["vuln_type"] == "XSS":
                xss_cluster = cluster
                break

        assert xss_cluster is not None, "Expected an XSS cluster"
        xss_urls = set(xss_cluster["urls"])
        assert "http://example.com/search" in xss_urls
        assert "http://example.com/profile" in xss_urls

    def test_multiple_clusters(self, graph_with_vulns):
        """There should be at least SQLi and XSS clusters."""
        clusters = graph_with_vulns.find_vulnerability_clusters()
        cluster_types = {c["vuln_type"] for c in clusters}
        assert "SQLi" in cluster_types
        assert "XSS" in cluster_types

    def test_pages_without_vulns_excluded(self, graph_with_vulns):
        """Pages with no vulnerabilities should not appear in any cluster."""
        clusters = graph_with_vulns.find_vulnerability_clusters()
        all_urls = set()
        for cluster in clusters:
            all_urls.update(cluster["urls"])
        assert "http://example.com/static" not in all_urls

    def test_single_page_cluster(self, empty_graph):
        """A cluster with one node is still valid."""
        empty_graph.add_node("http://example.com/only", depth=0)
        empty_graph.add_vulnerability("http://example.com/only", {
            "type": "SSRF",
            "severity": "high",
            "parameter": "url",
        })
        clusters = empty_graph.find_vulnerability_clusters()
        assert len(clusters) == 1
        assert clusters[0]["vuln_type"] == "SSRF"
        assert len(clusters[0]["urls"]) == 1

    def test_overlapping_vulnerabilities(self, graph_with_vulns):
        """
        /search has both SQLi and XSS.  It should appear in both clusters.
        """
        clusters = graph_with_vulns.find_vulnerability_clusters()
        search_url = "http://example.com/search"
        clusters_containing_search = [
            c for c in clusters if search_url in c["urls"]
        ]
        cluster_types = {c["vuln_type"] for c in clusters_containing_search}
        assert "SQLi" in cluster_types
        assert "XSS" in cluster_types

    def test_no_vulnerabilities_returns_empty_clusters(self, simple_linear_graph):
        """If no node has vulnerabilities, clusters list should be empty."""
        clusters = simple_linear_graph.find_vulnerability_clusters()
        assert clusters == []

    def test_all_same_vuln_type_single_cluster(self, empty_graph):
        """When every connected node has the same vuln type, there is exactly one cluster."""
        urls = [
            "http://example.com/a",
            "http://example.com/b",
            "http://example.com/c",
        ]
        for url in urls:
            empty_graph.add_node(url, depth=0)
            empty_graph.add_vulnerability(url, {
                "type": "SQLi", "severity": "critical", "parameter": "x"
            })
        # Connect them so they form one component
        empty_graph.add_edge(urls[0], urls[1])
        empty_graph.add_edge(urls[1], urls[2])
        clusters = empty_graph.find_vulnerability_clusters()
        assert len(clusters) == 1
        assert clusters[0]["vuln_type"] == "SQLi"
        assert len(clusters[0]["urls"]) == 3

    def test_cluster_structure_has_required_keys(self, graph_with_vulns):
        """Each cluster dict should contain vuln_type and urls keys."""
        clusters = graph_with_vulns.find_vulnerability_clusters()
        for cluster in clusters:
            assert "vuln_type" in cluster, f"Cluster missing vuln_type: {cluster}"
            assert "urls" in cluster, f"Cluster missing urls: {cluster}"
            assert isinstance(cluster["urls"], list)

    def test_many_distinct_vuln_types(self, empty_graph):
        """Each distinct vuln type across all nodes should form its own cluster."""
        vuln_types = ["SQLi", "XSS", "SSRF", "SSTI", "IDOR"]
        for i, vtype in enumerate(vuln_types):
            url = f"http://example.com/page{i}"
            empty_graph.add_node(url, depth=i)
            empty_graph.add_vulnerability(url, {
                "type": vtype, "severity": "high", "parameter": "p"
            })
        clusters = empty_graph.find_vulnerability_clusters()
        found_types = {c["vuln_type"] for c in clusters}
        assert found_types == set(vuln_types)


# ===================================================================
# d) Diagram Data Generation Tests
# ===================================================================

class TestDiagramDataGeneration:
    """Tests for generate_diagram_data()."""

    def test_output_is_json_serializable(self, graph_with_vulns):
        """The diagram data must be serializable to JSON without errors."""
        data = graph_with_vulns.generate_diagram_data()
        json_str = json.dumps(data)
        assert isinstance(json_str, str)

    def test_nodes_have_required_fields(self, graph_with_vulns):
        """Every node in the diagram data must have id, url, vulnerabilities, severity."""
        data = graph_with_vulns.generate_diagram_data()
        for node in data["nodes"]:
            assert "id" in node, f"Node missing id: {node}"
            assert "url" in node, f"Node missing url: {node}"
            assert "vulnerabilities" in node, f"Node missing vulnerabilities: {node}"
            assert "severity" in node, f"Node missing severity: {node}"

    def test_edges_have_required_fields(self, graph_with_vulns):
        """Every edge in the diagram data must have source and target."""
        data = graph_with_vulns.generate_diagram_data()
        for edge in data["edges"]:
            assert "source" in edge, f"Edge missing source: {edge}"
            assert "target" in edge, f"Edge missing target: {edge}"

    def test_cycle_edges_are_marked(self, simple_cycle_graph):
        """Edges that participate in a cycle should be flagged."""
        data = simple_cycle_graph.generate_diagram_data()
        cycle_edges = [e for e in data["edges"] if e.get("is_cycle_edge")]
        assert len(cycle_edges) >= 1, "Expected at least one cycle edge to be marked"

    def test_cluster_data_included(self, graph_with_vulns):
        """The diagram data should include vulnerability cluster information."""
        data = graph_with_vulns.generate_diagram_data()
        assert "clusters" in data
        assert isinstance(data["clusters"], list)
        assert len(data["clusters"]) >= 1

    def test_empty_graph_returns_valid_structure(self, empty_graph):
        """An empty graph should still produce a valid diagram structure."""
        data = empty_graph.generate_diagram_data()
        assert "nodes" in data
        assert "edges" in data
        assert "clusters" in data
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["clusters"] == []

    def test_diagram_data_node_count_matches(self, graph_with_vulns):
        """Number of diagram nodes should match number of graph nodes."""
        data = graph_with_vulns.generate_diagram_data()
        assert len(data["nodes"]) == len(graph_with_vulns.get_nodes())

    def test_diagram_data_edge_count_matches(self, graph_with_vulns):
        """Number of diagram edges should match number of graph edges."""
        data = graph_with_vulns.generate_diagram_data()
        assert len(data["edges"]) == len(graph_with_vulns.get_edges())

    def test_no_cycle_edges_in_acyclic_graph(self, simple_linear_graph):
        """In a graph without cycles, no edge should be marked as a cycle edge."""
        data = simple_linear_graph.generate_diagram_data()
        for edge in data["edges"]:
            assert not edge.get("is_cycle_edge"), (
                f"Edge {edge['source']} -> {edge['target']} incorrectly marked"
            )

    def test_severity_reflects_worst_vuln(self, empty_graph):
        """Node severity should reflect the worst vulnerability on that node."""
        empty_graph.add_node("http://example.com/a", depth=0)
        empty_graph.add_vulnerability("http://example.com/a", {
            "type": "XSS", "severity": "high", "parameter": "q"
        })
        empty_graph.add_vulnerability("http://example.com/a", {
            "type": "SQLi", "severity": "critical", "parameter": "id"
        })
        data = empty_graph.generate_diagram_data()
        node = data["nodes"][0]
        assert node["severity"] == "critical"

    def test_node_with_no_vulns_has_none_or_info_severity(self, empty_graph):
        """A node without vulnerabilities should have none or info severity."""
        empty_graph.add_node("http://example.com/safe", depth=0)
        data = empty_graph.generate_diagram_data()
        node = data["nodes"][0]
        assert node["severity"] in ("none", "info")

    def test_diagram_top_level_keys(self, graph_with_vulns):
        """Diagram data must contain nodes, edges, and clusters."""
        data = graph_with_vulns.generate_diagram_data()
        assert "nodes" in data
        assert "edges" in data
        assert "clusters" in data

    def test_self_loop_cycle_edge_marked(self, self_loop_graph):
        """A self-loop edge should be marked as a cycle edge in diagram data."""
        data = self_loop_graph.generate_diagram_data()
        assert len(data["edges"]) == 1
        assert data["edges"][0].get("is_cycle_edge") is True


# ===================================================================
# e) Integration-style Tests
# ===================================================================

class TestIntegrationWorkflow:
    """End-to-end tests combining graph build, cycle detection, clustering,
    and diagram generation."""

    def test_full_workflow(self, graph_with_vulns):
        """Build graph -> detect cycles -> find clusters -> generate diagram."""
        # 1. Verify graph was built
        assert len(graph_with_vulns.get_nodes()) == 5
        assert len(graph_with_vulns.get_edges()) == 4

        # 2. Detect cycles (this graph is acyclic)
        cycle_result = graph_with_vulns.detect_cycles()
        assert cycle_result["has_cycles"] is False

        # 3. Find clusters
        clusters = graph_with_vulns.find_vulnerability_clusters()
        assert len(clusters) >= 2

        # 4. Generate diagram
        diagram = graph_with_vulns.generate_diagram_data()
        assert "nodes" in diagram
        assert "edges" in diagram
        assert "clusters" in diagram
        json.dumps(diagram)  # must be serializable

    def test_full_workflow_with_cycles(self, simple_cycle_graph):
        """Full workflow on a graph that contains a cycle."""
        simple_cycle_graph.add_vulnerability("http://example.com/a", {
            "type": "SQLi", "severity": "critical", "parameter": "id"
        })

        cycles = simple_cycle_graph.detect_cycles()
        assert cycles["has_cycles"] is True

        clusters = simple_cycle_graph.find_vulnerability_clusters()
        assert len(clusters) == 1

        diagram = simple_cycle_graph.generate_diagram_data()
        cycle_edges = [e for e in diagram["edges"] if e.get("is_cycle_edge")]
        assert len(cycle_edges) >= 1

    def test_realistic_scan_data(self, empty_graph):
        """
        Simulate realistic scanner output: several pages with varying
        vulnerability types and link structures including cycles.
        """
        g = empty_graph

        pages = [
            ("http://target.com/", 0),
            ("http://target.com/login", 1),
            ("http://target.com/dashboard", 2),
            ("http://target.com/api/users", 2),
            ("http://target.com/api/admin", 3),
            ("http://target.com/search", 1),
            ("http://target.com/logout", 1),
        ]
        for url, depth in pages:
            g.add_node(url, depth=depth)

        links = [
            ("http://target.com/", "http://target.com/login"),
            ("http://target.com/", "http://target.com/search"),
            ("http://target.com/login", "http://target.com/dashboard"),
            ("http://target.com/dashboard", "http://target.com/api/users"),
            ("http://target.com/dashboard", "http://target.com/api/admin"),
            ("http://target.com/dashboard", "http://target.com/logout"),
            ("http://target.com/logout", "http://target.com/login"),
            ("http://target.com/api/admin", "http://target.com/dashboard"),
        ]
        for src, tgt in links:
            g.add_edge(src, tgt)

        g.add_vulnerability("http://target.com/login", {
            "type": "SQL Injection (Error-based, MySQL)",
            "severity": "critical",
            "parameter": "username",
        })
        g.add_vulnerability("http://target.com/search", {
            "type": "XSS (script_injection)",
            "severity": "high",
            "parameter": "q",
        })
        g.add_vulnerability("http://target.com/api/users", {
            "type": "IDOR (numeric)",
            "severity": "high",
            "parameter": "user_id",
        })
        g.add_vulnerability("http://target.com/api/admin", {
            "type": "Auth Bypass (Parameter Manipulation)",
            "severity": "critical",
            "parameter": "role",
        })

        cycles = g.detect_cycles()
        assert cycles["has_cycles"] is True

        clusters = g.find_vulnerability_clusters()
        assert len(clusters) >= 4

        diagram = g.generate_diagram_data()
        assert len(diagram["nodes"]) == 7
        assert len(diagram["edges"]) == 8
        json.dumps(diagram)

    def test_single_page_no_vulns(self, empty_graph):
        """Edge case: single node, no edges, no vulns."""
        empty_graph.add_node("http://example.com/only", depth=0)

        cycles = empty_graph.detect_cycles()
        assert cycles["has_cycles"] is False

        clusters = empty_graph.find_vulnerability_clusters()
        assert clusters == []

        diagram = empty_graph.generate_diagram_data()
        assert len(diagram["nodes"]) == 1
        assert diagram["edges"] == []
        assert diagram["clusters"] == []

    def test_all_nodes_same_vuln_type(self, empty_graph):
        """All nodes share the same vulnerability type -- one large cluster."""
        urls = [f"http://example.com/p{i}" for i in range(5)]
        for i, url in enumerate(urls):
            empty_graph.add_node(url, depth=i)
            empty_graph.add_vulnerability(url, {
                "type": "XSS", "severity": "high", "parameter": "input"
            })
        for i in range(4):
            empty_graph.add_edge(urls[i], urls[i + 1])

        clusters = empty_graph.find_vulnerability_clusters()
        assert len(clusters) == 1
        assert len(clusters[0]["urls"]) == 5

    def test_diagram_data_after_modifications(self, empty_graph):
        """Adding nodes/vulns after initial generation should update diagram."""
        empty_graph.add_node("http://example.com/a", depth=0)
        d1 = empty_graph.generate_diagram_data()
        assert len(d1["nodes"]) == 1

        empty_graph.add_node("http://example.com/b", depth=1)
        empty_graph.add_edge("http://example.com/a", "http://example.com/b")
        d2 = empty_graph.generate_diagram_data()
        assert len(d2["nodes"]) == 2
        assert len(d2["edges"]) == 1

    def test_complex_graph_full_pipeline(self, complex_multi_cycle_graph):
        """
        Full pipeline on the complex graph with two cycles and
        a disconnected linear component.
        """
        g = complex_multi_cycle_graph

        g.add_vulnerability("http://example.com/a", {
            "type": "SQLi", "severity": "critical", "parameter": "id"
        })
        g.add_vulnerability("http://example.com/c", {
            "type": "SQLi", "severity": "critical", "parameter": "q"
        })
        g.add_vulnerability("http://example.com/d", {
            "type": "XSS", "severity": "high", "parameter": "name"
        })
        g.add_vulnerability("http://example.com/f", {
            "type": "XSS", "severity": "high", "parameter": "search"
        })

        cycles = g.detect_cycles()
        assert cycles["has_cycles"] is True
        assert len(cycles["cycles"]) >= 2

        clusters = g.find_vulnerability_clusters()
        types = {c["vuln_type"] for c in clusters}
        assert "SQLi" in types
        assert "XSS" in types

        diagram = g.generate_diagram_data()
        assert len(diagram["nodes"]) == 7
        assert len(diagram["edges"]) == 7
        assert len(diagram["clusters"]) >= 2
        cycle_edges = [e for e in diagram["edges"] if e.get("is_cycle_edge")]
        assert len(cycle_edges) >= 1
        json.dumps(diagram)
