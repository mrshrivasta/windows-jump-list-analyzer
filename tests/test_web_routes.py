import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.ole_writer import build_minimal_ole
from tests.lnk_builder import build_lnk_bytes


def _make_jumplist_dir():
    tmpdir = tempfile.mkdtemp()
    lnk = build_lnk_bytes(local_target="E:\\exfil\\", drive_type=2, arguments="-enc SQBFAFgA")
    ole_bytes = build_minimal_ole({"1": lnk})
    path = os.path.join(tmpdir, "1234567890abcdef.automaticDestinations-ms")
    with open(path, "wb") as f:
        f.write(ole_bytes)
    return tmpdir


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = _make_jumplist_dir()
    try:
        # Run a real scan against a real temp dir containing a real jump list file
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert tmpdir.encode() in resp.data

        # Alerts page should load and contain at least one real alert
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"WJL-" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/jumplists",
        "scan_depth_limit": "3",
        "exclude_paths": "",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/jumplists" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
