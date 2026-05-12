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


def test_apk_meta_endpoints(app, client, tmp_path: Path):
    """Confirm /apk-meta GET (with lazy backfill) and POST (force) work."""
    from apk_web import apk_meta as _apk_meta

    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    # Build a minimal apktool tree the extractor can read.
    apktool = job_dir / "out" / "apktool"
    apktool.mkdir(parents=True)
    (apktool / "AndroidManifest.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.test" '
        'android:versionName="2.0" android:versionCode="3" '
        'android:compileSdkVersion="34">'
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>'
        '<application android:label="Tester"></application>'
        '</manifest>',
        encoding="utf-8",
    )
    (job_dir / "input.apk").write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # mini-zip

    _login(client)
    rv = client.get(f"/api/jobs/{job_id}/apk-meta")
    assert rv.status_code == 200
    payload = rv.get_json()["apk_meta"]
    assert payload["package"] == "com.example.test"
    assert payload["label"] == "Tester"
    assert payload["version_name"] == "2.0"
    assert payload["min_sdk"] == 24
    assert payload["target_sdk"] == 33

    # The lazy backfill must have persisted into meta.json.
    meta_now = store.get_meta(job_id)
    assert meta_now["apk_meta"]["package"] == "com.example.test"

    rv2 = client.post(f"/api/jobs/{job_id}/apk-meta")
    assert rv2.status_code == 200
    assert rv2.get_json()["apk_meta"]["package"] == "com.example.test"


def test_icon_endpoint_serves_inline_and_404s_when_missing(app, client, tmp_path: Path):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    job_dir = store.job_dir(job_id)
    # No metadata yet -> 404.
    _login(client)
    rv = client.get(f"/api/jobs/{job_id}/icon")
    assert rv.status_code == 404

    # Now seed an icon + meta and confirm we serve it inline.
    (job_dir / "meta").mkdir(parents=True)
    icon_bytes = bytes.fromhex(
        "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4"
        "890000000A49444154789C6300010000000500010D0A2DB40000000049454E44"
        "AE426082"
    )
    (job_dir / "meta" / "icon.png").write_bytes(icon_bytes)
    store.update_meta(job_id, apk_meta={"icon_rel": "meta/icon.png"})

    rv2 = client.get(f"/api/jobs/{job_id}/icon")
    assert rv2.status_code == 200
    assert rv2.headers["Content-Type"].startswith("image/png")
    # Inline, not attachment.
    cd = rv2.headers.get("Content-Disposition", "")
    assert "attachment" not in cd
    assert rv2.data == icon_bytes


def test_icon_endpoint_rejects_traversal(app, client):
    store = app.extensions["job_store"]
    job_id = store.create_job(original_filename="sample.apk")
    store.update_meta(job_id, apk_meta={"icon_rel": "../../../etc/passwd"})

    _login(client)
    rv = client.get(f"/api/jobs/{job_id}/icon")
    assert rv.status_code == 400


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
