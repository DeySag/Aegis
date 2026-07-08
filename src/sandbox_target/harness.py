import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_server(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = urllib.request.urlopen(f"{url}/ping", timeout=2)
            if resp.status == 200:
                return True
        except (urllib.error.URLError, ConnectionResetError, OSError):
            pass
        time.sleep(0.3)
    return False


def run_sandbox_test(
    sandbox_src: str | None = None,
    port: int | None = None,
    attack_payloads: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    if sandbox_src is None:
        sandbox_src = str(_proj / "src" / "sandbox_target")

    if port is None:
        port = find_free_port()

    url = f"http://127.0.0.1:{port}"
    tmpdir = None
    proc = None

    result: dict[str, Any] = {
        "passed": False,
        "startup_failed": False,
        "details": [],
        "errors": [],
        "port": port,
    }

    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="aegis_harness_"))
        shutil.copytree(sandbox_src, str(tmpdir / "sandbox_target"), dirs_exist_ok=True)
        shutil.copytree(str(_proj / "src"), str(tmpdir / "src"), dirs_exist_ok=True)

        app_module = "sandbox_target.app:app"
        cmd = [
            sys.executable, "-m", "uvicorn",
            app_module,
            "--port", str(port),
            "--host", "127.0.0.1",
        ]

        proc = subprocess.Popen(
            cmd,
            cwd=str(tmpdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if not wait_for_server(url):
            result["startup_failed"] = True
            result["errors"].append("Sandbox copy failed to start (syntax error or missing deps)")
            return result

        result["details"].append(f"Sandbox started at {url}")

        if attack_payloads is None:
            attack_payloads = [
                ("exploit_echo", "echo AEGIS_TEST_HARNESS"),
                ("exploit_dir", "dir"),
                ("benign_ping", "ping 127.0.0.1 -n 1"),
            ]

        exploitable_count = 0
        for name, payload in attack_payloads:
            try:
                encoded = payload.replace(" ", "%20")
                req = urllib.request.urlopen(
                    f"{url}/execute?cmd={encoded}", timeout=5
                )
                data = json.loads(req.read().decode())
                output = data.get("output", "")
                has_output = bool(output.strip())

                is_exploit = name.startswith("exploit_")
                is_error = output.startswith("[ERROR]") or output.startswith("[TIMEOUT]")
                if is_exploit and (not has_output or is_error):
                    result["details"].append(
                        f"  OK: {name} blocked (no output or error)"
                    )
                elif is_exploit and has_output:
                    result["details"].append(
                        f"  WARN: {name} produced output: {output[:80]}"
                    )
                    exploitable_count += 1
                elif not is_exploit and has_output:
                    result["details"].append(
                        f"  OK: {name} allowed (has output)"
                    )
                else:
                    result["details"].append(
                        f"  WARN: {name} had no output"
                    )
            except Exception as e:
                result["details"].append(f"  ERROR: {name} failed: {e}")
                result["errors"].append(str(e))

        result["exploitable_count"] = exploitable_count
        result["passed"] = exploitable_count == 0
        if result["passed"]:
            result["details"].append("All exploits blocked — test PASSED")
        else:
            result["details"].append(
                f"{exploitable_count} exploits still work — test FAILED"
            )

    except Exception as e:
        result["errors"].append(str(e))
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if tmpdir:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    return result


if __name__ == "__main__":
    print("=== Aegis Sandbox Test Harness ===")
    res = run_sandbox_test()
    print(f"\nTest {'PASSED' if res['passed'] else 'FAILED'}")
    print(f"Port: {res['port']}")
    for d in res["details"]:
        print(d)
    if res["errors"]:
        print(f"\nErrors: {res['errors']}")
