from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest


def _login(client) -> None:
    assert client.post("/login", data={"password": "test-password"}).status_code == 302


@pytest.fixture()
def app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    ws = tmp_path / "ws"
    tools = tmp_path / "tools"
    lib = tools / "jadx" / "lib"
    lib.mkdir(parents=True)
    (lib / "jadx-9.9.9-all.jar").write_bytes(b"")

    (tools / "apktool.jar").write_bytes(b"")

    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-password")
    monkeypatch.setenv("WORKSPACES_ROOT", str(ws))
    monkeypatch.setenv("TOOLS_ROOT", str(tools))
    monkeypatch.setenv("JOB_POOL_WORKERS", "1")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "false")

    # Prevent long-running decompile during upload tests
    monkeypatch.setenv("DECOMPILE_TIMEOUT_SEC", "1")

    from apk_web.app import create_app

    return create_app()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_dashboard_requires_login(client):
    rv = client.get("/")
    assert rv.status_code == 302
    assert "/login" in rv.headers.get("Location", "")


def test_api_requires_login(client):
    rv = client.get("/api/jobs")
    assert rv.status_code == 401


def test_login_failure_then_success(client):
    rv = client.post("/login", data={"password": "nope"}, follow_redirects=True)
    assert rv.status_code == 200

    rv = client.post(
        "/login",
        data={"password": "test-password"},
        follow_redirects=True,
    )
    assert rv.status_code == 200
    assert b"APK Wooper" in rv.data


def test_jobs_api_empty_when_authed(client):
    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get("/api/jobs")
    assert rv.status_code == 200
    assert rv.get_json()["jobs"] == []


def test_safe_relative_path_blocks_traversal(tmp_path: Path):
    from apk_web.path_safety import safe_relative_path

    root = tmp_path / "job"
    root.mkdir()

    ok = safe_relative_path(root, "out/jadx/Main.java")
    assert ok.is_file() is False
    assert "out" in ok.parts

    with pytest.raises(ValueError):
        safe_relative_path(root, "../evil")


def test_safe_relative_path_rejects_absolute(tmp_path: Path):
    from apk_web.path_safety import safe_relative_path

    root = tmp_path / "job"
    root.mkdir()

    with pytest.raises(ValueError):
        safe_relative_path(root, "/etc/passwd")


def test_java_runtimes_endpoint(client):
    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get("/api/java-runtimes")
    assert rv.status_code == 200
    payload = rv.get_json()
    assert "runtimes" in payload
    assert "minimum_major" in payload


def test_upload_accepts_apk(client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "apk_web.routes.api._enqueue",
        lambda job_id: None,
    )

    assert client.post("/login", data={"password": "test-password"}).status_code == 302

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest />")
    buf.seek(0)

    rv = client.post(
        "/api/upload",
        data={"file": (buf, "sample.apk")},
        content_type="multipart/form-data",
    )
    assert rv.status_code == 200
    job_id = rv.get_json()["job_id"]
    assert len(job_id) == 36


def test_job_download_streams_valid_zip_with_file_count(app, client):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    (job_dir / "out" / "jadx").mkdir(parents=True)
    (job_dir / "out" / "jadx" / "Main.java").write_bytes(b"class Main {}\n")
    (job_dir / "out" / "jadx" / "Helper.java").write_bytes(b"class Helper {}\n")

    _login(client)
    rv = client.get(f"/api/jobs/{job_id}/download")

    assert rv.status_code == 200
    assert rv.headers["Content-Type"] == "application/zip"
    cd = rv.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert ".zip" in cd

    file_count = int(rv.headers["X-Job-File-Count"])
    # at least the two java files plus meta.json + job.log seeded by JobStore
    assert file_count >= 4

    zf = zipfile.ZipFile(io.BytesIO(rv.data))
    names = set(zf.namelist())
    assert "out/jadx/Main.java" in names
    assert "out/jadx/Helper.java" in names
    assert zf.read("out/jadx/Main.java") == b"class Main {}\n"
    assert zf.testzip() is None


def test_raw_file_download_serves_attachment(app, client):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    (job_dir / "out" / "jadx").mkdir(parents=True)
    target = job_dir / "out" / "jadx" / "Main.java"
    target.write_bytes(b"class Main {}\n")

    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get(f"/api/jobs/{job_id}/raw?path=out/jadx/Main.java")
    assert rv.status_code == 200
    disposition = rv.headers.get("Content-Disposition", "")
    assert "attachment" in disposition
    assert "Main.java" in disposition
    assert rv.data == b"class Main {}\n"


def test_raw_file_download_rejects_traversal(app, client):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")

    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get(f"/api/jobs/{job_id}/raw?path=../../etc/passwd")
    assert rv.status_code == 400


def test_tree_response_includes_node_count(app, client):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    (job_dir / "out" / "jadx").mkdir(parents=True)
    (job_dir / "out" / "jadx" / "Main.java").write_text("", encoding="utf-8")

    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get(f"/api/jobs/{job_id}/tree")
    assert rv.status_code == 200
    payload = rv.get_json()
    assert "node_count" in payload
    assert "max_nodes" in payload
    assert payload["node_count"] >= 4  # root, out, jadx, Main.java (plus meta.json, etc.)


def test_tree_prioritizes_jadx_when_truncated(app, client, monkeypatch: pytest.MonkeyPatch):
    from apk_web.routes import api

    monkeypatch.setattr(api, "_MAX_TREE_NODES", 6)
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    (job_dir / "out" / "apktool" / "res").mkdir(parents=True)
    (job_dir / "out" / "apktool" / "res" / "values.xml").write_text("", encoding="utf-8")
    (job_dir / "out" / "jadx" / "sources").mkdir(parents=True)
    (job_dir / "out" / "jadx" / "sources" / "MainActivity.java").write_text(
        "class MainActivity {}",
        encoding="utf-8",
    )

    assert client.post("/login", data={"password": "test-password"}).status_code == 302
    rv = client.get(f"/api/jobs/{job_id}/tree")

    assert rv.status_code == 200
    tree = rv.get_json()["tree"]
    out = next(child for child in tree["children"] if child["name"] == "out")
    assert out["children"][0]["name"] == "jadx"
