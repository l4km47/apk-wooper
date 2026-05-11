"""Docker-based MobSF installer helpers.

We deliberately limit ourselves to ``docker`` for one-click install/start/stop
because it works the same on Windows, macOS, and Linux and avoids the
pitfalls of bootstrapping the MobSF source repo. Users who prefer the
pip / source path still have the manual instructions in the offline panel
and in the README.

All subprocess invocations use ``shell=False`` with an explicit argv list.
Container name and image are constrained by :data:`DEFAULT_CONTAINER` and
:data:`DEFAULT_IMAGE`; callers may not pass arbitrary args through.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

_LOG = logging.getLogger(__name__)


DEFAULT_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
DEFAULT_CONTAINER = "apk_wooper_mobsf"
DEFAULT_PORT = 8000


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass
class DockerStatus:
    available: bool
    version: str
    image_present: bool
    container_running: bool
    container_exists: bool
    container_id: str
    container_status: str
    host_port: Optional[int]
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "available": self.available,
            "version": self.version,
            "image_present": self.image_present,
            "container_running": self.container_running,
            "container_exists": self.container_exists,
            "container_id": self.container_id,
            "container_status": self.container_status,
            "host_port": self.host_port,
            "error": self.error,
            "image": DEFAULT_IMAGE,
            "container_name": DEFAULT_CONTAINER,
        }


def _docker_bin() -> Optional[str]:
    return shutil.which("docker")


def _run(argv: List[str], *, timeout: float = 30.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (-1, "", f"{type(exc).__name__}: {exc}")
    return (proc.returncode, proc.stdout or "", proc.stderr or "")


def docker_status(
    *, image: str = DEFAULT_IMAGE, container: str = DEFAULT_CONTAINER
) -> DockerStatus:
    """Snapshot Docker availability plus the MobSF image/container state."""
    binary = _docker_bin()
    if not binary:
        return DockerStatus(
            available=False,
            version="",
            image_present=False,
            container_running=False,
            container_exists=False,
            container_id="",
            container_status="",
            host_port=None,
            error="docker CLI not on PATH",
        )

    rc, ver_out, ver_err = _run([binary, "--version"], timeout=6)
    if rc != 0:
        return DockerStatus(
            available=False,
            version="",
            image_present=False,
            container_running=False,
            container_exists=False,
            container_id="",
            container_status="",
            host_port=None,
            error=(ver_err or "docker --version failed").strip(),
        )
    version = ver_out.strip()

    # Image presence: `docker image inspect <image>` is fast and exits 1 if missing.
    rc, _, _ = _run([binary, "image", "inspect", image], timeout=10)
    image_present = rc == 0

    # Container state: `docker inspect --format '{{json .}}' <container>`.
    rc, out, _ = _run(
        [
            binary,
            "inspect",
            "--format",
            "{{json .State}}|{{json .NetworkSettings.Ports}}",
            container,
        ],
        timeout=10,
    )
    container_exists = rc == 0
    container_running = False
    container_id = ""
    container_status = ""
    host_port: Optional[int] = None
    if container_exists:
        try:
            state_raw, ports_raw = out.strip().split("|", 1)
            state = json.loads(state_raw) if state_raw else {}
            ports = json.loads(ports_raw) if ports_raw and ports_raw != "null" else {}
        except (ValueError, json.JSONDecodeError):
            state, ports = {}, {}
        container_running = bool(state.get("Running"))
        container_status = str(state.get("Status") or "")
        # Try to recover the host port mapping for 8000/tcp.
        binding = ports.get("8000/tcp") if isinstance(ports, dict) else None
        if isinstance(binding, list) and binding:
            try:
                host_port = int(binding[0].get("HostPort") or 0) or None
            except (TypeError, ValueError):
                host_port = None
        # Cheap way to grab the short id.
        rc, id_out, _ = _run(
            [binary, "inspect", "--format", "{{.Id}}", container], timeout=6
        )
        if rc == 0:
            container_id = id_out.strip()[:12]

    return DockerStatus(
        available=True,
        version=version,
        image_present=image_present,
        container_running=container_running,
        container_exists=container_exists,
        container_id=container_id,
        container_status=container_status,
        host_port=host_port,
    )


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def pull_image_stream(image: str = DEFAULT_IMAGE) -> Iterator[str]:
    """Yield lines from ``docker pull <image>`` as the daemon emits them.

    Always finishes with a synthetic ``[exit <code>]`` line so the UI can
    detect completion even when the pull is silent.
    """
    binary = _docker_bin()
    if not binary:
        yield "[error] docker CLI not on PATH"
        yield "[exit 127]"
        return
    yield f"$ docker pull {image}"
    try:
        proc = subprocess.Popen(
            [binary, "pull", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        yield f"[error] failed to spawn docker: {exc}"
        yield "[exit -1]"
        return
    assert proc.stdout is not None
    try:
        for raw in proc.stdout:
            yield raw.rstrip("\r\n")
    finally:
        proc.stdout.close()
        rc = proc.wait()
        yield f"[exit {rc}]"


def start_container(
    *,
    image: str = DEFAULT_IMAGE,
    container: str = DEFAULT_CONTAINER,
    host_port: int = DEFAULT_PORT,
) -> Tuple[bool, str, Dict[str, object]]:
    """Idempotently start the MobSF container."""
    binary = _docker_bin()
    if not binary:
        return (False, "docker CLI not on PATH", {})
    if not isinstance(host_port, int) or not (1 <= host_port <= 65535):
        return (False, "host_port out of range", {})

    status = docker_status(image=image, container=container)
    if status.container_running:
        return (
            True,
            f"already running on host port {status.host_port or host_port}",
            {"id": status.container_id, "host_port": status.host_port or host_port},
        )

    # If a stopped container by the same name exists, prefer `start` to keep
    # any prior state.
    if status.container_exists:
        rc, out, err = _run([binary, "start", container], timeout=20)
        if rc != 0:
            return (False, (err or out or "docker start failed").strip(), {})
        # Re-read to get fresh state.
        post = docker_status(image=image, container=container)
        return (
            True,
            f"started existing container on host port {post.host_port or host_port}",
            {"id": post.container_id, "host_port": post.host_port or host_port},
        )

    # Need to pull first if missing.
    if not status.image_present:
        return (
            False,
            f"image {image} is not pulled; run install first",
            {"needs_pull": True},
        )

    rc, out, err = _run(
        [
            binary,
            "run",
            "-d",
            "--name",
            container,
            "-p",
            f"{host_port}:8000",
            image,
        ],
        timeout=60,
    )
    if rc != 0:
        return (False, (err or out or "docker run failed").strip(), {})
    cid = out.strip()[:12]
    return (
        True,
        f"started new container on host port {host_port}",
        {"id": cid, "host_port": host_port},
    )


def stop_container(
    *, container: str = DEFAULT_CONTAINER, remove: bool = False
) -> Tuple[bool, str]:
    binary = _docker_bin()
    if not binary:
        return (False, "docker CLI not on PATH")
    rc, out, err = _run([binary, "stop", container], timeout=30)
    if rc != 0:
        return (False, (err or out or "docker stop failed").strip())
    if remove:
        rc2, out2, err2 = _run([binary, "rm", container], timeout=15)
        if rc2 != 0:
            return (False, (err2 or out2 or "docker rm failed").strip())
        return (True, "stopped and removed")
    return (True, "stopped")
