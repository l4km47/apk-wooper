"""Tests for the built-in MobSF plugin (client + routes)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib import error

import pytest

from apk_web.plugins.mobsf import client as mobsf_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status: int, body: bytes = b""):
        self._status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self._status


class _UrlopenSpy:
    """Records (Request, timeout) pairs and returns canned responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: List[Tuple[Any, Any]] = []

    def __call__(self, req, timeout=None):
        self.calls.append((req, timeout))
        if not self.responses:
            raise AssertionError("urlopen called more times than expected")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _spy(monkeypatch, responses):
    spy = _UrlopenSpy(responses)
    monkeypatch.setattr(mobsf_client.request, "urlopen", spy)
    return spy


def _req_url(req) -> str:
    if isinstance(req, str):
        return req
    if hasattr(req, "full_url"):
        return req.full_url
    if hasattr(req, "get_full_url"):
        return req.get_full_url()
    return str(req)


# ---------------------------------------------------------------------------
# Client unit tests
# ---------------------------------------------------------------------------


def test_ping_ok(monkeypatch):
    spy = _spy(monkeypatch, [_FakeResponse(200, b"<html/>")])
    client = mobsf_client.MobsfClient("http://localhost:8000/", "secret")
    ok, msg = client.ping()
    assert ok is True
    assert "200" in msg
    # Trailing slash should have been stripped, then re-added by the GET.
    assert _req_url(spy.calls[0][0]) == "http://localhost:8000/"


def test_ping_fail_url_error(monkeypatch):
    _spy(monkeypatch, [error.URLError("connection refused")])
    client = mobsf_client.MobsfClient("http://localhost:8000")
    ok, msg = client.ping()
    assert ok is False
    assert "connection refused" in msg


def test_ping_no_url_configured():
    client = mobsf_client.MobsfClient("")
    ok, msg = client.ping()
    assert ok is False
    assert "not configured" in msg.lower()


def test_upload_sends_multipart_with_auth_header(monkeypatch, tmp_path: Path):
    apk = tmp_path / "demo.apk"
    apk.write_bytes(b"PK\x03\x04hello-apk")
    body = json.dumps(
        {"file_name": "demo.apk", "hash": "abc123", "scan_type": "apk"}
    ).encode("utf-8")
    spy = _spy(monkeypatch, [_FakeResponse(200, body)])

    client = mobsf_client.MobsfClient("http://localhost:8000", "supersecretkey")
    out = client.upload(apk)

    assert out == {"file_name": "demo.apk", "hash": "abc123", "scan_type": "apk"}
    req = spy.calls[0][0]
    assert _req_url(req) == "http://localhost:8000/api/v1/upload"
    # Werkzeug-style: headers are normalized to title case.
    headers = {k.lower(): v for k, v in req.header_items()}
    assert headers["authorization"] == "supersecretkey"
    assert headers["content-type"].startswith("multipart/form-data; boundary=")
    raw = req.data or b""
    assert b'filename="demo.apk"' in raw
    assert b"PK\x03\x04hello-apk" in raw


def test_upload_raises_on_missing_file(tmp_path: Path):
    client = mobsf_client.MobsfClient("http://localhost:8000", "k")
    with pytest.raises(mobsf_client.MobsfError):
        client.upload(tmp_path / "missing.apk")


def test_scan_form_encoded_and_authed(monkeypatch):
    body = json.dumps({"status": "queued"}).encode("utf-8")
    spy = _spy(monkeypatch, [_FakeResponse(200, body)])

    client = mobsf_client.MobsfClient("http://localhost:8000", "k")
    out = client.scan("apk", "demo.apk", "abc123")
    assert out == {"status": "queued"}

    req = spy.calls[0][0]
    assert _req_url(req) == "http://localhost:8000/api/v1/scan"
    raw = (req.data or b"").decode("utf-8")
    assert "hash=abc123" in raw
    assert "scan_type=apk" in raw
    assert "file_name=demo.apk" in raw


def test_scan_requires_hash():
    client = mobsf_client.MobsfClient("http://localhost:8000", "k")
    with pytest.raises(mobsf_client.MobsfError):
        client.scan("apk", "demo.apk", "")


def test_report_url_branches():
    client = mobsf_client.MobsfClient("http://localhost:8000/")
    assert client.report_url("") == "http://localhost:8000/recent_scans/"
    url = client.report_url("abc/def")
    assert url.startswith("http://localhost:8000/static_analyzer/?checksum=")
    assert "abc%2Fdef" in url


def test_config_roundtrip_via_instance(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("MOBSF_URL", raising=False)
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    instance = tmp_path / "instance"

    # No file yet -> falls back to defaults / env.
    cfg = mobsf_client.load_config(str(instance))
    assert cfg["url"] == "http://localhost:8000"
    assert cfg["api_key"] == ""

    saved = mobsf_client.save_config(str(instance), "http://mobsf.local:9090", "k123")
    assert saved == {"url": "http://mobsf.local:9090", "api_key": "k123"}

    cfg2 = mobsf_client.load_config(str(instance))
    assert cfg2["url"] == "http://mobsf.local:9090"
    assert cfg2["api_key"] == "k123"


def test_http_error_surfaces_as_mobsf_error(monkeypatch):
    err = error.HTTPError(
        "http://localhost:8000/api/v1/upload",
        500,
        "Internal Server Error",
        {},
        io.BytesIO(b"boom"),
    )
    _spy(monkeypatch, [err])
    client = mobsf_client.MobsfClient("http://localhost:8000", "k")
    with pytest.raises(mobsf_client.MobsfError) as ei:
        client._request("POST", "/api/v1/upload", data=b"x")
    assert "500" in str(ei.value)


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mobsf_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, isolated_plugins_config):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")
    monkeypatch.setenv("WORKSPACES_ROOT", str(tmp_path / "workspaces"))
    from apk_web.app import create_app

    app = create_app()
    app.testing = True
    # Use a temp instance dir so the test never writes to the real one.
    app.instance_path = str(tmp_path / "instance")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    return app, client


def test_index_renders_offline_panel(monkeypatch, mobsf_app):
    app, client = mobsf_app
    _spy(monkeypatch, [error.URLError("no MobSF here")])
    res = client.get("/plugins/mobsf/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "MobSF is not reachable" in html
    # The new offline panel walks through the GitHub install flow.
    assert "Install from GitHub" in html
    assert "Clone repo" in html


def test_index_renders_iframe_when_ok(monkeypatch, mobsf_app):
    app, client = mobsf_app
    _spy(monkeypatch, [_FakeResponse(200, b"<html/>")])
    res = client.get("/plugins/mobsf/?hash=deadbeef")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "MobSF reachable" in html
    assert "static_analyzer/?checksum=deadbeef" in html


def test_config_post_persists_to_instance(monkeypatch, mobsf_app, tmp_path: Path):
    app, client = mobsf_app
    res = client.post(
        "/plugins/mobsf/config",
        json={"url": "http://mobsf.local:9000", "api_key": "topsecret"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["ok"] is True
    persisted = json.loads((Path(app.instance_path) / "mobsf.json").read_text())
    assert persisted == {"url": "http://mobsf.local:9000", "api_key": "topsecret"}


def test_config_post_rejects_bad_url(mobsf_app):
    app, client = mobsf_app
    res = client.post("/plugins/mobsf/config", json={"url": "not-a-url"})
    assert res.status_code == 400


def test_detect_route(monkeypatch, mobsf_app):
    app, client = mobsf_app
    _spy(monkeypatch, [_FakeResponse(200, b"<html/>")])
    res = client.post(
        "/plugins/mobsf/detect",
        json={"url": "http://localhost:8000", "api_key": "k"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True


def test_scan_route_uploads_and_returns_report_url(monkeypatch, mobsf_app):
    app, client = mobsf_app
    workspaces = Path(app.config["WORKSPACES_ROOT"])
    job_dir = workspaces / "job-abc"
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "input.apk").write_bytes(b"PK\x03\x04stub")

    upload_body = json.dumps(
        {"file_name": "input.apk", "hash": "h1", "scan_type": "apk"}
    ).encode("utf-8")
    scan_body = json.dumps({"status": "ok"}).encode("utf-8")
    _spy(
        monkeypatch,
        [
            _FakeResponse(200, b"<html/>"),  # ping
            _FakeResponse(200, upload_body),  # upload
            _FakeResponse(200, scan_body),  # scan
        ],
    )

    res = client.post("/plugins/mobsf/scan/job-abc")
    assert res.status_code == 200, res.get_data(as_text=True)
    body = res.get_json()
    assert body["ok"] is True
    assert body["hash"] == "h1"
    assert "static_analyzer/?checksum=h1" in body["report_url"]


def test_scan_route_rejects_bad_job_id(mobsf_app):
    app, client = mobsf_app
    res = client.post("/plugins/mobsf/scan/..%2Fevil")
    assert res.status_code in (400, 404)


def test_scan_route_missing_apk(monkeypatch, mobsf_app):
    app, client = mobsf_app
    workspaces = Path(app.config["WORKSPACES_ROOT"])
    (workspaces / "no-apk-job").mkdir(parents=True, exist_ok=True)
    # No urlopen call should happen because we 404 before contacting MobSF.
    _spy(monkeypatch, [])
    res = client.post("/plugins/mobsf/scan/no-apk-job")
    assert res.status_code == 404


def test_scan_route_reports_mobsf_offline(monkeypatch, mobsf_app):
    app, client = mobsf_app
    workspaces = Path(app.config["WORKSPACES_ROOT"])
    job_dir = workspaces / "job-offline"
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "input.apk").write_bytes(b"PK\x03\x04stub")

    _spy(monkeypatch, [error.URLError("offline")])
    res = client.post("/plugins/mobsf/scan/job-offline")
    assert res.status_code == 502
    body = res.get_json()
    assert body["ok"] is False
    assert "not reachable" in body["error"].lower()


def test_api_mobsf_status_endpoint(monkeypatch, mobsf_app):
    app, client = mobsf_app
    _spy(monkeypatch, [_FakeResponse(200, b"<html/>")])
    res = client.get("/api/mobsf/status")
    assert res.status_code == 200
    body = res.get_json()
    assert body["enabled"] is True
    assert body["ok"] is True


def test_api_mobsf_status_disabled(monkeypatch, mobsf_app):
    app, client = mobsf_app
    app.config["ENABLE_MOBSF"] = False
    res = client.get("/api/mobsf/status")
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is False
    assert body["enabled"] is False


# ---------------------------------------------------------------------------
# GitHub installer
# ---------------------------------------------------------------------------


from apk_web.plugins.mobsf import github_installer as gh_installer  # noqa: E402


def _gh_status(**overrides):
    base = dict(
        git_available=True,
        git_version="git version 2.45.0",
        python_available=True,
        python_version="Python 3.14.0",
        repo_path="/tmp/mobsf/Mobile-Security-Framework-MobSF",
        repo_cloned=False,
        setup_done=False,
        pid=None,
        host_port=None,
        running=False,
        started_at=None,
        platform="unix",
        setup_command="setup.sh",
        run_command="run.sh",
    )
    base.update(overrides)
    return gh_installer.GithubStatus(**base)


def test_gh_status_detects_missing_git(monkeypatch, tmp_path):
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: None)
    monkeypatch.setattr(
        gh_installer, "_run", lambda *a, **kw: (0, "Python 3.14.0\n", "")
    )
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {})
    snap = gh_installer.github_status(tmp_path)
    assert snap.git_available is False
    assert snap.python_available is True


def test_gh_status_detects_repo_cloned(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    monkeypatch.setattr(
        gh_installer,
        "_run",
        lambda argv, **kw: (0, "git version 2.45.0\n" if "--version" in argv else "Python 3.14.0\n", ""),
    )
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {})
    snap = gh_installer.github_status(tmp_path)
    assert snap.repo_cloned is True
    assert snap.setup_done is False
    assert snap.running is False


def test_gh_status_running_pid(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    (repo / "venv").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    monkeypatch.setattr(
        gh_installer,
        "_run",
        lambda argv, **kw: (0, "git version 2.45.0\n" if "--version" in argv else "Python 3.14.0\n", ""),
    )
    monkeypatch.setattr(
        gh_installer, "_load_state",
        lambda _r: {"pid": 4242, "host_port": 8000, "started_at": 1.0},
    )
    monkeypatch.setattr(gh_installer, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(gh_installer, "_port_open", lambda *_a, **_kw: True)
    snap = gh_installer.github_status(tmp_path)
    assert snap.running is True
    assert snap.pid == 4242
    assert snap.host_port == 8000


def test_gh_status_clears_state_when_pid_dead(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    monkeypatch.setattr(
        gh_installer,
        "_run",
        lambda argv, **kw: (0, "git version 2.45.0\n" if "--version" in argv else "Python 3.14.0\n", ""),
    )
    monkeypatch.setattr(
        gh_installer, "_load_state",
        lambda _r: {"pid": 9999, "host_port": 8000},
    )
    monkeypatch.setattr(gh_installer, "_pid_alive", lambda _pid: False)
    cleared = {"called": False}
    monkeypatch.setattr(
        gh_installer, "_clear_state", lambda _r: cleared.__setitem__("called", True)
    )
    snap = gh_installer.github_status(tmp_path)
    assert snap.running is False
    assert snap.pid is None
    assert cleared["called"] is True


def test_clone_stream_when_git_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: None)
    lines = list(gh_installer.clone_stream(tmp_path))
    assert any("git is not on PATH" in l for l in lines)
    assert lines[-1] == "[exit 127]"


def test_clone_stream_runs_git_clone(monkeypatch, tmp_path):
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    captured = {}

    def fake_stream(argv, *, cwd=None):
        captured["argv"] = argv
        yield "Cloning into..."
        yield "[exit 0]"

    monkeypatch.setattr(gh_installer, "_stream_subprocess", fake_stream)
    lines = list(gh_installer.clone_stream(tmp_path))
    assert "clone" in captured["argv"]
    assert gh_installer.MOBSF_REPO_URL in captured["argv"]
    assert "[exit 0]" in lines[-1]


def test_clone_stream_pulls_when_repo_exists(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    captured = {}

    def fake_stream(argv, *, cwd=None):
        captured["argv"] = argv
        yield "Already up to date."
        yield "[exit 0]"

    monkeypatch.setattr(gh_installer, "_stream_subprocess", fake_stream)
    lines = list(gh_installer.clone_stream(tmp_path))
    assert captured["argv"][:2] == ["/usr/bin/git", "pull"]
    assert any("Already up to date." in l for l in lines)


def test_setup_stream_when_not_cloned(monkeypatch, tmp_path):
    lines = list(gh_installer.setup_stream(tmp_path))
    assert any("not cloned" in l for l in lines)
    assert lines[-1] == "[exit 1]"


def test_setup_stream_runs_setup_script(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    script_name = "setup.bat" if gh_installer._is_windows() else "setup.sh"
    (repo / script_name).write_text("#!/bin/sh\necho ok")

    captured = {}

    def fake_stream(argv, *, cwd=None):
        captured["argv"] = argv
        captured["cwd"] = cwd
        yield "running"
        yield "[exit 0]"

    monkeypatch.setattr(gh_installer, "_stream_subprocess", fake_stream)
    lines = list(gh_installer.setup_stream(tmp_path))
    assert captured["cwd"] == repo
    assert script_name in " ".join(captured["argv"])
    assert lines[-1].startswith("[exit ")


def test_start_validates_port(tmp_path):
    ok, msg, _ = gh_installer.start(tmp_path, host_port=70000)
    assert ok is False
    assert "port" in msg.lower()


def test_start_when_not_cloned(monkeypatch, tmp_path):
    ok, msg, details = gh_installer.start(tmp_path, host_port=8000)
    assert ok is False
    assert details.get("needs_clone") is True


def test_runtime_check_uses_poetry_run_python(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    repo.mkdir(parents=True)
    calls = []

    def fake_run(argv, *, cwd=None, timeout=30.0):
        calls.append((argv, cwd, timeout))
        return (0, "", "")

    monkeypatch.setattr(gh_installer, "_run", fake_run)
    ok, msg = gh_installer._runtime_check(repo)
    assert ok is True
    argv, cwd, timeout = calls[0]
    assert argv[:3] == [gh_installer.sys.executable, "-m", "poetry"]
    assert argv[3:5] == ["run", "python"]
    assert "import " in " ".join(argv)
    assert cwd == repo


def test_repair_runtime_falls_back_to_runtime_package(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    repo.mkdir(parents=True)
    calls = []

    def fake_run(argv, *, cwd=None, timeout=30.0):
        calls.append(argv)
        if "install" in argv and "--only" in argv:
            return (1, "", "poetry install failed")
        return (0, "installed", "")

    monkeypatch.setattr(gh_installer, "_run", fake_run)
    monkeypatch.setattr(gh_installer, "_runtime_check", lambda _repo: (True, "ready"))

    ok, msg = gh_installer._repair_runtime(repo)
    assert ok is True
    assert any("pip" in argv and "install" in argv for argv in calls)
    assert gh_installer._runtime_import_name() in msg or "Installed" in msg


def test_start_blocks_when_runtime_repair_fails(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=True, running=False),
    )
    monkeypatch.setattr(
        gh_installer,
        "_ensure_runtime_ready",
        lambda _repo: (False, "waitress is missing and repair failed"),
    )
    called = {"spawn": False}
    monkeypatch.setattr(
        gh_installer,
        "_spawn_run_script",
        lambda *_a, **_k: called.__setitem__("spawn", True),
    )

    ok, msg, details = gh_installer.start(tmp_path, host_port=8000)
    assert ok is False
    assert "waitress" in msg
    assert details["needs_setup"] is True
    assert called["spawn"] is False


def test_start_short_circuits_when_running(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=True, running=True, pid=4242, host_port=8000),
    )
    ok, msg, details = gh_installer.start(tmp_path, host_port=8000)
    assert ok is True
    assert details["pid"] == 4242
    assert "already running" in msg


class _FakePopen:
    """Minimal Popen stand-in for tests that exercise lifecycle helpers."""

    def __init__(self, pid=12345, returncode=None):
        self.pid = pid
        self._returncode = returncode
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.signals = []
        self.waited = False

    def poll(self):
        return self._returncode

    def wait(self, timeout=None):
        self.waited = True
        if self._returncode is None:
            # Simulate that wait blocks until terminate() decides the exit.
            self._returncode = 0
            self.returncode = 0
        return self._returncode

    def terminate(self):
        self.terminated = True
        if self._returncode is None:
            self._returncode = 143
            self.returncode = 143

    def kill(self):
        self.killed = True
        if self._returncode is None:
            self._returncode = 137
            self.returncode = 137

    def send_signal(self, sig):
        self.signals.append(sig)
        if self._returncode is None:
            self._returncode = 0
            self.returncode = 0


@pytest.fixture(autouse=True)
def _reset_mobsf_proc():
    """Make sure module-level Popen state doesn't leak between tests."""
    gh_installer._MOBSF_PROC = None
    gh_installer._MOBSF_TOOLS_ROOT = None
    yield
    gh_installer._MOBSF_PROC = None
    gh_installer._MOBSF_TOOLS_ROOT = None


def test_start_spawns_run_script(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=True, running=False),
    )
    log_path = tmp_path / "fake-run.log"
    fake_proc = _FakePopen(pid=12345)
    monkeypatch.setattr(
        gh_installer,
        "_spawn_run_script",
        lambda r, p: (fake_proc, log_path, ""),
    )
    monkeypatch.setattr(
        gh_installer, "_ensure_runtime_ready", lambda _repo: (True, "ready")
    )
    saved = {}
    monkeypatch.setattr(
        gh_installer, "_save_state", lambda _r, state: saved.update(state)
    )
    # Monitor thread would otherwise call _load_state on the temp dir.
    monkeypatch.setattr(gh_installer.threading, "Thread", _NoopThread)

    ok, msg, details = gh_installer.start(tmp_path, host_port=8123)
    assert ok is True
    assert details["pid"] == 12345
    assert details["host_port"] == 8123
    assert saved["pid"] == 12345
    assert saved["host_port"] == 8123
    # In-memory Popen registered.
    assert gh_installer._MOBSF_PROC is fake_proc
    assert gh_installer._MOBSF_TOOLS_ROOT == tmp_path


class _NoopThread:
    def __init__(self, *a, **kw):
        pass
    def start(self):
        pass


def test_start_registers_atexit_hook(monkeypatch, tmp_path):
    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=True, running=False),
    )
    monkeypatch.setattr(
        gh_installer,
        "_spawn_run_script",
        lambda r, p: (_FakePopen(pid=999), tmp_path / "x.log", ""),
    )
    monkeypatch.setattr(
        gh_installer, "_ensure_runtime_ready", lambda _repo: (True, "ready")
    )
    monkeypatch.setattr(gh_installer, "_save_state", lambda _r, _s: None)
    monkeypatch.setattr(gh_installer.threading, "Thread", _NoopThread)
    monkeypatch.setattr(gh_installer, "_ATEXIT_REGISTERED", False, raising=False)
    registered = []
    monkeypatch.setattr(
        gh_installer.atexit, "register", lambda fn: registered.append(fn) or fn
    )
    ok, _, _ = gh_installer.start(tmp_path, host_port=8000)
    assert ok is True
    assert registered, "atexit.register should be invoked"
    assert registered[0] is gh_installer._atexit_terminate


def test_stop_when_no_state(monkeypatch, tmp_path):
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {})
    ok, msg = gh_installer.stop(tmp_path)
    assert ok is True
    assert "no tracked" in msg


def test_stop_when_pid_already_gone(monkeypatch, tmp_path):
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {"pid": 99})
    monkeypatch.setattr(gh_installer, "_pid_alive", lambda _p: False)
    cleared = {"called": False}
    monkeypatch.setattr(
        gh_installer, "_clear_state", lambda _r: cleared.__setitem__("called", True)
    )
    ok, msg = gh_installer.stop(tmp_path)
    assert ok is True
    assert cleared["called"] is True


def test_stop_kills_running_pid_unix(monkeypatch, tmp_path):
    if gh_installer._is_windows():
        pytest.skip("posix-only path")
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {"pid": 4242})
    alive = iter([True, False])
    monkeypatch.setattr(gh_installer, "_pid_alive", lambda _p: next(alive))
    killed = {}
    monkeypatch.setattr(gh_installer.os, "kill", lambda p, s: killed.update(pid=p, sig=s))
    monkeypatch.setattr(gh_installer.time, "sleep", lambda _s: None)
    monkeypatch.setattr(gh_installer, "_clear_state", lambda _r: None)
    ok, msg = gh_installer.stop(tmp_path)
    assert ok is True
    assert killed["pid"] == 4242


def test_stop_uses_inmemory_popen_first(monkeypatch, tmp_path):
    """When the dashboard spawned MobSF itself we should ``terminate`` the
    in-memory Popen instead of going through taskkill / os.kill."""
    fake = _FakePopen(pid=5555)
    gh_installer._MOBSF_PROC = fake
    gh_installer._MOBSF_TOOLS_ROOT = tmp_path

    # If anyone reaches for the PID-based path, blow up loudly.
    def _boom(*a, **kw):  # pragma: no cover - guard
        raise AssertionError("PID-based kill path should not be taken")

    monkeypatch.setattr(gh_installer, "_run", _boom)
    monkeypatch.setattr(gh_installer.os, "kill", _boom)

    cleared = {"called": False}
    monkeypatch.setattr(
        gh_installer, "_clear_state", lambda _r: cleared.__setitem__("called", True)
    )

    ok, msg = gh_installer.stop(tmp_path)
    assert ok is True
    assert fake.terminated is True or fake.signals  # at least one stop signal
    assert "5555" in msg
    assert cleared["called"] is True
    assert gh_installer._MOBSF_PROC is None


def test_monitor_thread_updates_state_on_exit(monkeypatch, tmp_path):
    fake = _FakePopen(pid=4321, returncode=None)
    gh_installer._MOBSF_PROC = fake
    saved = {}
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {"pid": 4321})
    monkeypatch.setattr(
        gh_installer, "_save_state", lambda _r, state: saved.update(state)
    )

    # Simulate proc.wait() returning a non-zero exit code.
    fake._returncode = None  # ensure wait actually flips it

    def fake_wait(timeout=None):
        fake._returncode = 7
        fake.returncode = 7
        return 7

    fake.wait = fake_wait  # type: ignore[assignment]

    gh_installer._monitor(fake, tmp_path)
    assert saved.get("running") is False
    assert saved.get("exit_code") == 7
    assert gh_installer._MOBSF_PROC is None


def test_status_uses_popen_poll_when_handle_present(monkeypatch, tmp_path):
    fake = _FakePopen(pid=7777, returncode=None)
    gh_installer._MOBSF_PROC = fake
    gh_installer._MOBSF_TOOLS_ROOT = tmp_path

    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    monkeypatch.setattr(
        gh_installer,
        "_run",
        lambda argv, **kw: (
            0,
            "git version 2.45.0\n" if "--version" in argv else "Python 3.14.0\n",
            "",
        ),
    )
    monkeypatch.setattr(
        gh_installer, "_load_state", lambda _r: {"pid": 7777, "host_port": 8000}
    )
    # _pid_alive must NOT be consulted when we have a live Popen.
    monkeypatch.setattr(
        gh_installer,
        "_pid_alive",
        lambda _p: (_ for _ in ()).throw(AssertionError("should be skipped")),
    )
    monkeypatch.setattr(gh_installer, "_port_open", lambda *_a, **_k: True)
    snap = gh_installer.github_status(tmp_path)
    assert snap.running is True
    assert snap.pid == 7777
    assert snap.managed_in_process is True


def test_status_records_exit_code_when_popen_dead(monkeypatch, tmp_path):
    fake = _FakePopen(pid=9999, returncode=12)
    gh_installer._MOBSF_PROC = fake

    repo = gh_installer.repo_path(tmp_path)
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(gh_installer, "_git_bin", lambda: "/usr/bin/git")
    monkeypatch.setattr(
        gh_installer,
        "_run",
        lambda argv, **kw: (
            0,
            "git version 2.45.0\n" if "--version" in argv else "Python 3.14.0\n",
            "",
        ),
    )
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {"pid": 9999})
    snap = gh_installer.github_status(tmp_path)
    assert snap.running is False
    assert snap.exit_code == 12
    assert snap.pid is None
    assert snap.managed_in_process is True


def test_spawn_uses_create_no_window_on_windows(monkeypatch, tmp_path):
    if not gh_installer._is_windows():
        pytest.skip("windows-only flags")
    repo = gh_installer.repo_path(tmp_path)
    repo.mkdir(parents=True)
    (repo / "run.bat").write_text("@echo MobSF stub\r\n")
    captured = {}

    class _PopenStub:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            self.pid = 11111

    monkeypatch.setattr(gh_installer.subprocess, "Popen", _PopenStub)
    proc, _log, err = gh_installer._spawn_run_script(repo, 8000)
    assert err == ""
    flags = captured["kwargs"].get("creationflags", 0)
    # CREATE_NO_WINDOW must be on, DETACHED_PROCESS must be off.
    assert flags & gh_installer._CREATE_NO_WINDOW
    detached = getattr(gh_installer.subprocess, "DETACHED_PROCESS", 0x00000008)
    assert not (flags & detached)
    # CREATE_NEW_PROCESS_GROUP should still be set so we can Ctrl+Break later.
    new_group = getattr(
        gh_installer.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200
    )
    assert flags & new_group
    # We call Poetry through the dashboard interpreter, not bare PATH poetry
    # and not upstream run.bat.
    assert captured["argv"][:3] == [
        gh_installer.sys.executable,
        "-m",
        "poetry",
    ]
    assert "waitress-serve" in captured["argv"]


def test_spawn_no_new_session_on_unix(monkeypatch, tmp_path):
    if gh_installer._is_windows():
        pytest.skip("posix-only path")
    repo = gh_installer.repo_path(tmp_path)
    repo.mkdir(parents=True)
    (repo / "run.sh").write_text("#!/bin/sh\necho hi\n")
    captured = {}

    class _PopenStub:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            self.pid = 22222

    monkeypatch.setattr(gh_installer.subprocess, "Popen", _PopenStub)
    proc, _log, err = gh_installer._spawn_run_script(repo, 8001)
    assert err == ""
    # MobSF stays in the dashboard's session so it dies on SIGHUP.
    assert captured["kwargs"].get("start_new_session", False) is False
    assert captured["argv"][:3] == [
        gh_installer.sys.executable,
        "-m",
        "poetry",
    ]
    assert "gunicorn" in captured["argv"]


def test_atexit_terminate_kills_running_child(monkeypatch, tmp_path):
    fake = _FakePopen(pid=33333, returncode=None)
    gh_installer._MOBSF_PROC = fake
    gh_installer._MOBSF_TOOLS_ROOT = tmp_path
    monkeypatch.setattr(gh_installer, "_load_state", lambda _r: {"pid": 33333})
    saved = {}
    monkeypatch.setattr(
        gh_installer, "_save_state", lambda _r, state: saved.update(state)
    )
    gh_installer._atexit_terminate()
    assert fake.terminated is True or fake.killed is True or fake.signals
    assert saved.get("running") is False


def test_atexit_terminate_is_noop_when_no_child():
    gh_installer._MOBSF_PROC = None
    # Should not raise.
    gh_installer._atexit_terminate()


# ---------------------------------------------------------------------------
# GitHub routes
# ---------------------------------------------------------------------------


def test_github_status_route(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=True, setup_done=True),
    )
    res = client.get("/plugins/mobsf/github/status")
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["github"]["repo_cloned"] is True
    assert body["github"]["setup_done"] is True


def test_github_clone_route_streams(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(
        gh_installer,
        "clone_stream",
        lambda _root: iter(["Cloning...", "[exit 0]"]),
    )
    res = client.post("/plugins/mobsf/github/clone")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "Cloning..." in body
    assert "[exit 0]" in body


def test_github_setup_route_streams(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(
        gh_installer,
        "setup_stream",
        lambda _root: iter(["Running setup", "[exit 0]"]),
    )
    res = client.post("/plugins/mobsf/github/setup")
    assert res.status_code == 200
    assert "Running setup" in res.get_data(as_text=True)


def test_github_start_route_persists_url(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(
        gh_installer,
        "start",
        lambda _root, *, host_port=8000: (
            True, "ok", {"pid": 1234, "host_port": host_port}
        ),
    )
    monkeypatch.setenv("MOBSF_URL", "")
    res = client.post("/plugins/mobsf/github/start", json={"host_port": 8123})
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body.get("url_updated") == "http://localhost:8123"
    persisted = json.loads((Path(app.instance_path) / "mobsf.json").read_text())
    assert persisted["url"] == "http://localhost:8123"


def test_github_start_route_propagates_failure(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(
        gh_installer,
        "start",
        lambda _root, *, host_port=8000: (False, "not cloned", {"needs_clone": True}),
    )
    res = client.post("/plugins/mobsf/github/start", json={"host_port": 8000})
    assert res.status_code == 502
    body = res.get_json()
    assert body["ok"] is False
    assert body.get("needs_clone") is True


def test_github_start_route_validates_port(mobsf_app):
    app, client = mobsf_app
    res = client.post("/plugins/mobsf/github/start", json={"host_port": "abc"})
    assert res.status_code == 400


def test_github_stop_route(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(gh_installer, "stop", lambda _root: (True, "stopped"))
    res = client.post("/plugins/mobsf/github/stop", json={})
    assert res.status_code == 200
    assert res.get_json()["message"] == "stopped"


def test_github_log_route(monkeypatch, mobsf_app):
    app, client = mobsf_app
    monkeypatch.setattr(gh_installer, "tail_log", lambda _root: "last 5 lines of run.log")
    res = client.get("/plugins/mobsf/github/log")
    assert res.status_code == 200
    assert "run.log" in res.get_data(as_text=True)


def test_offline_index_shows_github_panel(monkeypatch, mobsf_app):
    app, client = mobsf_app
    _spy(monkeypatch, [error.URLError("offline")])
    monkeypatch.setattr(
        gh_installer,
        "github_status",
        lambda _root: _gh_status(repo_cloned=False, setup_done=False),
    )
    res = client.get("/plugins/mobsf/")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Install from GitHub" in html
    assert "Clone repo" in html
    assert "Start MobSF" in html
