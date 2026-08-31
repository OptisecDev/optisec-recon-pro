"""Test for Eternal Core (app/, port 8100) item B: app/main.py's
CORSMiddleware combined allow_origins=["*"] with allow_credentials=True, an
invalid combination per the CORS spec. allow_credentials is now False.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app.main import app


def test_cors_preflight_with_wildcard_origin_has_no_credentials_header():
    with TestClient(app) as client:
        resp = client.options(
            "/health",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert resp.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in {
        k.lower() for k in resp.headers.keys()
    }
