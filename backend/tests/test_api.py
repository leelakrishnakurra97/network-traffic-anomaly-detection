"""
Integration tests for FastAPI endpoints:
- User registration and login
- RBAC enforcement (User cannot access Admin endpoints)
- PCAP upload and analysis flow
- Non-DNS and Corrupt PCAP error handling
"""

import os
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import init_db

@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c

def test_root_and_health(client):
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["system"] == "NETSENTINEL"

    h_res = client.get("/health")
    assert h_res.status_code == 200
    assert h_res.json()["status"] == "HEALTHY"

def test_auth_and_rbac(client):
    # 1. Register a normal user
    reg_res = client.post("/auth/register", json={
        "name": "Alice Analyst",
        "email": "alice@soc.net",
        "password": "Password123!",
        "role": "user"
    })
    assert reg_res.status_code in (201, 400) # 201 created or 400 if already exists

    # 2. Login
    login_res = client.post("/auth/login", json={
        "email": "alice@soc.net",
        "password": "Password123!"
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    user_headers = {"Authorization": f"Bearer {token}"}

    # 3. Access current user profile
    me_res = client.get("/auth/me", headers=user_headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == "alice@soc.net"
    assert me_res.json()["role"] == "user"

    # 4. Attempt to access Admin endpoint with regular user token -> MUST BE 403 FORBIDDEN
    forbidden_res = client.get("/admin/dashboard", headers=user_headers)
    assert forbidden_res.status_code == 403
    assert "Administrative privileges required" in forbidden_res.json()["detail"]

    # 5. Login as default Admin -> MUST BE 200 OK
    admin_login = client.post("/auth/login", json={
        "email": "admin@netsentinel.sec",
        "password": "AdminPassword@2026"
    })
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    admin_dash = client.get("/admin/dashboard", headers=admin_headers)
    assert admin_dash.status_code == 200
    assert "active_model" in admin_dash.json()

def test_pcap_upload_flow(client):
    # Login as analyst
    login_res = client.post("/auth/login", json={
        "email": "analyst@netsentinel.sec",
        "password": "AnalystPassword@2026"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Upload valid benign PCAP
    benign_pcap = "uploads/sample_pcaps/benign_dns_traffic.pcap"
    if os.path.exists(benign_pcap):
        with open(benign_pcap, "rb") as f:
            res = client.post(
                "/analysis/upload",
                headers=headers,
                files={"file": ("benign_test.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert res.status_code == 201
        data = res.json()
        assert data["query_count"] == 5
        assert "risk_score" in data
        assert "risk_level" in data
        analysis_id = data["id"]

        # Fetch detail
        det_res = client.get(f"/analysis/{analysis_id}", headers=headers)
        assert det_res.status_code == 200

    # 2. Upload non-DNS PCAP -> 422 Unprocessable Entity
    non_dns_pcap = "uploads/sample_pcaps/non_dns_traffic.pcap"
    if os.path.exists(non_dns_pcap):
        with open(non_dns_pcap, "rb") as f:
            res_nd = client.post(
                "/analysis/upload",
                headers=headers,
                files={"file": ("non_dns.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert res_nd.status_code == 422
        assert "No usable DNS traffic" in res_nd.json()["detail"]

    # 3. Upload corrupt file -> 400 Bad Request
    corrupt_pcap = "uploads/sample_pcaps/corrupt_file.pcap"
    if os.path.exists(corrupt_pcap):
        with open(corrupt_pcap, "rb") as f:
            res_c = client.post(
                "/analysis/upload",
                headers=headers,
                files={"file": ("corrupt.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        assert res_c.status_code == 400
