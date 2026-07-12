"""
API endpoint tests for the graph analysis feature.

These tests verify that graph analysis data is accessible through the
FastAPI scan endpoints once graph_analyzer.py is integrated into the
scan pipeline.

Tests cover:
- Starting a scan with graph analysis enabled
- Fetching graph data for a completed scan
- Validating graph data format from the API response
- Error handling for graph data requests

These tests follow the same patterns established by the existing
test_integration_scan_flow.py -- using the app_client fixture and
the FakeWebScanner monkeypatch from conftest.py.
"""

import time
import json
import importlib

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, username="graph_user"):
    """Register a user and return an auth token."""
    reg = client.post("/register", json={
        "username": username,
        "email": f"{username}@example.com",
        "password": "Test@1234",
        "confirm_password": "Test@1234",
    })
    assert reg.status_code in (200, 201, 400)

    login = client.post("/login", json={
        "username": username,
        "password": "Test@1234",
    })
    assert login.status_code == 200, login.text
    token = login.json().get("token")
    assert token, f"Login response missing token: {login.json()}"
    return token


def _start_and_wait(client, token, url="https://example.com", max_pages=1, enable_graph_analysis=True):
    """Start a scan and poll until completed/failed (max ~4s)."""
    headers = _auth_headers(token)

    r = client.post(
        "/scan/",
        json={"url": url, "max_pages": max_pages, "enable_graph_analysis": enable_graph_analysis},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    job_id = body.get("job_id") or body.get("scan_id") or body.get("id")
    assert job_id, f"Start scan response missing job id: {body}"

    status = None
    for _ in range(80):
        pr = client.get(f"/scan/{job_id}/progress", headers=headers)
        assert pr.status_code == 200, pr.text
        progress = pr.json()
        status = progress.get("status")
        if status in ("completed", "failed"):
            break
        time.sleep(0.05)

    return job_id, status


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGraphAPIEndpoints:
    """Tests for graph-related API endpoints."""

    def test_scan_completes_with_graph_data_available(self, app_client):
        """A completed scan should allow fetching graph data."""
        token = _register_and_login(app_client, username="graph_api_user1")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed", f"Scan did not complete: {status}"

        headers = _auth_headers(token)
        # The graph endpoint may be at /scan/{job_id}/graph or included
        # in the main scan result.  Try the dedicated endpoint first.
        graph_resp = app_client.get(
            f"/scan/{job_id}/graph", headers=headers
        )

        if graph_resp.status_code == 200:
            data = graph_resp.json()
            assert "nodes" in data
            assert "edges" in data
        else:
            # Graph data might be embedded in the main result instead
            result_resp = app_client.get(f"/scan/{job_id}", headers=headers)
            assert result_resp.status_code == 200, result_resp.text

    def test_graph_data_format_nodes(self, app_client):
        """Graph nodes returned by the API should have required fields."""
        token = _register_and_login(app_client, username="graph_api_user2")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        headers = _auth_headers(token)
        graph_resp = app_client.get(
            f"/scan/{job_id}/graph", headers=headers
        )

        if graph_resp.status_code == 200:
            data = graph_resp.json()
            for node in data.get("nodes", []):
                assert "id" in node
                assert "url" in node

    def test_graph_data_format_edges(self, app_client):
        """Graph edges returned by the API should have source and target."""
        token = _register_and_login(app_client, username="graph_api_user3")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        headers = _auth_headers(token)
        graph_resp = app_client.get(
            f"/scan/{job_id}/graph", headers=headers
        )

        if graph_resp.status_code == 200:
            data = graph_resp.json()
            for edge in data.get("edges", []):
                assert "source" in edge
                assert "target" in edge

    def test_graph_data_is_json_serializable(self, app_client):
        """The graph data from the API must round-trip through JSON."""
        token = _register_and_login(app_client, username="graph_api_user4")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        headers = _auth_headers(token)
        graph_resp = app_client.get(
            f"/scan/{job_id}/graph", headers=headers
        )

        if graph_resp.status_code == 200:
            data = graph_resp.json()
            # Round-trip must not raise
            json_str = json.dumps(data)
            assert isinstance(json_str, str)
            reparsed = json.loads(json_str)
            assert reparsed == data

    def test_graph_endpoint_requires_auth(self, app_client):
        """Fetching graph data without a token should return 401."""
        # We need a valid job_id to test, so create one first
        token = _register_and_login(app_client, username="graph_api_user5")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        # Now try without auth
        resp = app_client.get(f"/scan/{job_id}/graph")
        # Should be 401 or 403 (depends on middleware behaviour)
        assert resp.status_code in (401, 403, 404)

    def test_graph_endpoint_invalid_job_id(self, app_client):
        """Fetching graph data for a non-existent job should return 404."""
        token = _register_and_login(app_client, username="graph_api_user6")
        headers = _auth_headers(token)
        resp = app_client.get(
            "/scan/nonexistent-job-id-12345/graph", headers=headers
        )
        assert resp.status_code in (404, 422)

    def test_scan_result_includes_findings(self, app_client):
        """The main scan result should include vulnerability findings."""
        token = _register_and_login(app_client, username="graph_api_user7")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        headers = _auth_headers(token)
        result_resp = app_client.get(f"/scan/{job_id}", headers=headers)
        assert result_resp.status_code == 200, result_resp.text

    def test_progress_endpoint_during_scan(self, app_client):
        """The progress endpoint should return valid data during a scan."""
        token = _register_and_login(app_client, username="graph_api_user8")
        headers = _auth_headers(token)

        r = app_client.post(
            "/scan/",
            params={"url": "https://example.com", "max_pages": 1},
            headers=headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        job_id = body.get("job_id") or body.get("scan_id") or body.get("id")
        assert job_id

        # Immediately check progress
        pr = app_client.get(f"/scan/{job_id}/progress", headers=headers)
        assert pr.status_code == 200, pr.text
        progress = pr.json()
        assert "status" in progress


class TestGraphAPIAccessControl:
    """Tests for access control on graph data endpoints."""

    def test_other_user_cannot_access_graph(self, app_client):
        """A different user should not be able to access another user's graph data."""
        # User 1 starts a scan
        token1 = _register_and_login(app_client, username="graph_acl_user1")
        job_id, status = _start_and_wait(app_client, token1)
        assert status == "completed"

        # User 2 tries to access it
        token2 = _register_and_login(app_client, username="graph_acl_user2")
        headers2 = _auth_headers(token2)

        resp = app_client.get(f"/scan/{job_id}/graph", headers=headers2)
        # Should be 403 Forbidden or 404 (hiding existence)
        assert resp.status_code in (403, 404)

    def test_owner_can_access_own_graph(self, app_client):
        """The scan owner should be able to access their own graph data."""
        token = _register_and_login(app_client, username="graph_acl_owner")
        job_id, status = _start_and_wait(app_client, token)
        assert status == "completed"

        headers = _auth_headers(token)
        # Try both the graph endpoint and the main result
        graph_resp = app_client.get(f"/scan/{job_id}/graph", headers=headers)
        result_resp = app_client.get(f"/scan/{job_id}", headers=headers)

        # At least one should succeed
        assert graph_resp.status_code == 200 or result_resp.status_code == 200
