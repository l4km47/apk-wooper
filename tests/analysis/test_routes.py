"""Route-level tests for the analysis API."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from apk_web.app import create_app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WORKSPACES_ROOT", str(tmp_path / "ws"))
    monkeypatch.setenv("TOOLS_ROOT", str(tmp_path / "tools"))
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-pass")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ANALYSIS_AUTO_RUN", "0")
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as c:
        rv = c.post("/login", data={"password": "test-pass"}, follow_redirects=False)
        assert rv.status_code in (200, 302)
        yield c, app


def _make_job_with_findings(app, job_id: str, findings: list[dict]) -> Path:
    store = app.extensions["job_store"]
    job_dir = store.root / job_id
    (job_dir / "out" / "jadx").mkdir(parents=True)
    store._write_meta(  # noqa: SLF001 - test setup
        job_id,
        {
            "id": job_id,
            "status": "done",
            "created_at": "2026-01-01T00:00:00+00:00",
            "updated_at": "2026-01-01T00:00:00+00:00",
            "original_filename": "demo.apk",
            "error_message": None,
            "log_excerpt": "",
            "analysis_status": "done",
            "analysis_high_count": sum(1 for f in findings if f["severity"] == "high"),
            "analysis_findings_count": len(findings),
        },
    )
    a_dir = job_dir / "analysis"
    a_dir.mkdir(parents=True)
    (a_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (a_dir / "summary.json").write_text(
        json.dumps(
            {
                "findings_count": len(findings),
                "files_scanned": 1,
                "duration_sec": 0.1,
                "by_severity": {"high": sum(1 for f in findings if f["severity"] == "high")},
                "by_category": {},
                "by_rule": {},
            }
        ),
        encoding="utf-8",
    )
    return job_dir


def _sample_findings() -> list[dict]:
    return [
        {
            "id": "abc1",
            "rule_id": "secret.firebase_api_key",
            "category": "secret",
            "severity": "high",
            "title": "Firebase API key",
            "file": "out/jadx/x.java",
            "line": 1,
            "column": 1,
            "match": "AIza...0000",
            "full_match": "AIzaSy0000000000000000000000000000000",
            "snippet": "key = \"AIza...\"",
            "tool": "regex",
            "confidence": 0.95,
        },
        {
            "id": "abc2",
            "rule_id": "net.http_url",
            "category": "network",
            "severity": "low",
            "title": "URL",
            "file": "out/jadx/x.java",
            "line": 2,
            "column": 1,
            "match": "https://api.example.com",
            "full_match": "https://api.example.com",
            "snippet": "",
            "tool": "regex",
            "confidence": 0.6,
        },
    ]


def test_analysis_findings_returns_pagination(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())

    rv = c.get(f"/api/jobs/{job_id}/analysis")
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["total"] == 2
    assert len(data["findings"]) == 2

    rv = c.get(f"/api/jobs/{job_id}/analysis?severity=high")
    data = rv.get_json()
    assert data["total"] == 1
    assert data["findings"][0]["rule_id"] == "secret.firebase_api_key"

    rv = c.get(f"/api/jobs/{job_id}/analysis?q=example")
    data = rv.get_json()
    assert data["total"] == 1
    assert data["findings"][0]["rule_id"] == "net.http_url"


def test_analysis_summary_endpoint(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.get(f"/api/jobs/{job_id}/analysis/summary")
    assert rv.status_code == 200
    summary = rv.get_json()
    assert summary["findings_count"] == 2


def test_analysis_status_reports_meta(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.get(f"/api/jobs/{job_id}/analysis/status")
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["status"] == "done"
    assert data["high_count"] == 1
    assert data["running"] is False


def test_analysis_export_csv(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.get(f"/api/jobs/{job_id}/analysis/export?format=csv")
    assert rv.status_code == 200
    body = rv.data.decode("utf-8")
    assert "rule_id" in body.splitlines()[0]
    assert "secret.firebase_api_key" in body
    assert "net.http_url" in body
    assert "attachment" in rv.headers["Content-Disposition"]


def test_analysis_export_sarif(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.get(f"/api/jobs/{job_id}/analysis/export?format=sarif")
    assert rv.status_code == 200
    payload = json.loads(rv.data)
    assert payload["version"] == "2.1.0"
    runs = payload["runs"]
    assert len(runs) == 1
    rules = {r["id"] for r in runs[0]["tool"]["driver"]["rules"]}
    assert "secret.firebase_api_key" in rules


def test_analysis_export_rejects_unknown_format(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.get(f"/api/jobs/{job_id}/analysis/export?format=xml")
    assert rv.status_code == 400


def test_analysis_ignores_round_trip(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.post(
        f"/api/jobs/{job_id}/analysis/ignores",
        json={"rules": ["net.http_url"], "fingerprints": ["abc1"]},
    )
    assert rv.status_code == 200
    rv = c.get(f"/api/jobs/{job_id}/analysis/ignores")
    data = rv.get_json()
    assert data["rules"] == ["net.http_url"]
    assert data["fingerprints"] == ["abc1"]


def test_analysis_rerun_starts_background_job(client) -> None:
    c, app = client
    job_id = str(uuid.uuid4())
    _make_job_with_findings(app, job_id, _sample_findings())
    rv = c.post(f"/api/jobs/{job_id}/analysis")
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "running"


def test_analysis_routes_reject_invalid_job_id(client) -> None:
    c, _ = client
    for route in (
        "/api/jobs/not-a-uuid/analysis",
        "/api/jobs/not-a-uuid/analysis/summary",
        "/api/jobs/not-a-uuid/analysis/status",
        "/api/jobs/not-a-uuid/analysis/export?format=csv",
    ):
        rv = c.get(route)
        assert rv.status_code == 404, route


def test_analysis_routes_404_when_job_missing(client) -> None:
    c, _ = client
    missing = str(uuid.uuid4())
    rv = c.get(f"/api/jobs/{missing}/analysis")
    assert rv.status_code == 404
