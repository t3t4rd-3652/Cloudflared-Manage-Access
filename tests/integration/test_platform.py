import subprocess
import sys
import time

import pytest

from cma.core.instance import InstanceLock, IpcServer, send_command
from cma.platform.winjob import ProcessJob


@pytest.mark.skipif(sys.platform != "win32", reason="Job Object : Windows uniquement")
def test_job_object_kills_children_when_closed():
    job = ProcessJob()
    assert job.active
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], creationflags=subprocess.CREATE_NO_WINDOW
    )
    try:
        assert job.assign(child.pid)
        job.close()
        child.wait(timeout=10)
        assert child.returncode is not None
    finally:
        if child.poll() is None:
            child.kill()


def test_instance_lock_is_exclusive(paths):
    first = InstanceLock(paths.lock_file)
    second = InstanceLock(paths.lock_file)
    assert first.acquire()
    assert not second.acquire()
    first.release()
    assert second.acquire()
    second.release()


def test_ipc_roundtrip(paths):
    received = []

    def handler(message):
        received.append(message)
        return {"ok": True, "echo": message.get("value")}

    server = IpcServer(paths, handler)
    server.start()
    try:
        time.sleep(0.2)
        assert send_command(paths, {"cmd": "ping", "value": 42}) == {"ok": True, "echo": 42}
        assert received == [{"cmd": "ping", "value": 42}]
    finally:
        server.stop()


def test_send_command_without_instance_returns_none(paths):
    assert send_command(paths, {"cmd": "status"}, timeout=1) is None
