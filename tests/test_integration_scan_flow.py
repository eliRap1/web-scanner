import time


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_feature_4_6_end_to_end_scan_flow(app_client):
    # 1) register (may be 200/201, or 400 if already exists)
    r = app_client.post("/register", json={
        "username": "e2e_user",
        "email": "e2e_user@example.com",
        "password": "Aa123456!",
        "confirm_password": "Aa123456!"
    })
    assert r.status_code in (200, 201, 400)

    # 2) login
    r = app_client.post("/login", json={
        "username": "e2e_user",
        "password": "Aa123456!"
    })
    assert r.status_code == 200
    token = r.json().get("token")
    assert token, f"Login response missing token: {r.json()}"

    headers = _auth_headers(token)

    # 3) start scan — body must be JSON (credentials must not appear in query strings)
    r = app_client.post("/scan/", json={"url": "https://example.com", "max_pages": 1}, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    job_id = body.get("job_id") or body.get("scan_id") or body.get("id")
    assert job_id, f"Start scan response missing job id: {body}"

    # 4) poll progress until completed/failed
    status = None
    for _ in range(80):
        pr = app_client.get(f"/scan/{job_id}/progress", headers=headers)
        assert pr.status_code == 200, pr.text
        progress = pr.json()
        status = progress.get("status")
        if status in ("completed", "failed"):
            break
        time.sleep(0.05)

    assert status == "completed", f"Expected completed, got {status}"

    # 5) fetch final status/result
    st = app_client.get(f"/scan/{job_id}", headers=headers)
    assert st.status_code == 200, st.text

    # 6) logs should be accessible for owner (Feature 4.2)
    lg = app_client.get(f"/scan/{job_id}/logs", headers=headers)
    assert lg.status_code in (200, 204), lg.text
