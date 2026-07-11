import base64
import json
import os
import pickle
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

_proj = Path(__file__).resolve().parents[2]


class _EchoMarker:
    """Standard pickle __reduce__ demo gadget: unpickling this runs a
    harmless echo. Used only to prove/disprove RCE via pickle.loads() on
    our own isolated sandbox copy — never against a real target."""

    def __reduce__(self):
        return (os.system, ("echo KAVACH_TEST_HARNESS",))


def _endpoint_config(vuln_type: str, port: int) -> tuple[str, str, list[tuple[str, str]]]:
    """Return (endpoint, query_param, default [(name, payload), ...]) for a
    given vuln_type. Payload names starting with 'exploit_' are expected to
    be blocked after a correct patch; 'benign_' payloads must keep working."""
    if vuln_type == "sql_injection":
        return "/search", "name", [
            ("benign_lookup", "alice"),
            ("benign_miss", "nonexistent_user"),
            ("exploit_or_tautology", "nonexistent' OR '1'='1' --"),
        ]
    if vuln_type == "path_traversal":
        # One "../" escapes reports/ into sandbox_target/ itself — stable
        # across both a direct run and this harness's isolated temp copy.
        return "/download", "file", [
            ("benign_report", "q3_summary.txt"),
            ("exploit_traverse_source", "../app.py"),
        ]
    if vuln_type == "deserialization":
        exploit_token = base64.b64encode(pickle.dumps(_EchoMarker())).decode()
        benign_token = base64.b64encode(json.dumps({"user": "alice"}).encode()).decode()
        return "/session", "token", [
            ("benign_session", benign_token),
            ("exploit_pickle_rce", exploit_token),
        ]
    if vuln_type == "ssrf":
        return "/webhook", "url", [
            ("benign_self_ping", f"http://127.0.0.1:{port}/ping"),
            ("exploit_hostname_bypass", f"http://localhost:{port}/ping"),
        ]
    # default: command_injection
    # A leading ";" only works as chaining if the shell interprets it; once
    # shlex.split() removes shell=True, ";" becomes argv[0] of a
    # nonexistent program, so this cleanly distinguishes "still vulnerable"
    # (echo runs, chained) from "patched" (FileNotFoundError) regardless of
    # host OS — unlike bare "echo"/"dir", which are real standalone
    # executables on Linux and would "succeed" even after a correct patch.
    return "/execute", "cmd", [
        ("exploit_chain_semicolon", "; echo KAVACH_TEST_HARNESS"),
        ("benign_echo", "echo KAVACH_TEST_HARNESS"),
    ]


def _is_exploitable(vuln_type: str, name: str, data: dict) -> bool:
    if not name.startswith("exploit_"):
        return False
    if vuln_type == "sql_injection":
        return len(data.get("results", []) or []) > 0
    if vuln_type == "path_traversal":
        content = data.get("content", "") or ""
        return data.get("error") is None and bool(content.strip())
    if vuln_type == "deserialization":
        return data.get("error") is None
    if vuln_type == "ssrf":
        return data.get("status") == 200
    # command_injection
    output = data.get("output", "") or ""
    is_error = output.startswith("[ERROR]") or output.startswith("[TIMEOUT]")
    return bool(output.strip()) and not is_error


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
    vuln_type: str = "command_injection",
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
        tmpdir = Path(tempfile.mkdtemp(prefix="kavach_harness_"))
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

        endpoint, param, default_payloads = _endpoint_config(vuln_type, port)
        if attack_payloads is None:
            attack_payloads = default_payloads
        result["endpoint"] = endpoint
        result["vuln_type"] = vuln_type

        exploitable_count = 0
        for name, payload in attack_payloads:
            try:
                encoded = urllib.parse.quote(payload)
                req = urllib.request.urlopen(
                    f"{url}{endpoint}?{param}={encoded}", timeout=5
                )
                data = json.loads(req.read().decode())

                is_exploit = name.startswith("exploit_")
                exploitable = _is_exploitable(vuln_type, name, data)
                # "has_response" is a rough proxy for "the request produced
                # something" — used only to flag suspicious no-op benign calls.
                has_response = any(
                    bool(v) for k, v in data.items()
                    if k not in ("error", "status_code") and v not in (None, "")
                )

                if is_exploit and exploitable:
                    result["details"].append(
                        f"  WARN: {name} succeeded: {str(data)[:120]}"
                    )
                    exploitable_count += 1
                elif is_exploit and not exploitable:
                    result["details"].append(f"  OK: {name} blocked")
                elif not is_exploit and has_response:
                    result["details"].append(f"  OK: {name} allowed (has response)")
                else:
                    result["details"].append(f"  WARN: {name} had no response")
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
    print("=== KAVACH Sandbox Test Harness ===")
    res = run_sandbox_test()
    print(f"\nTest {'PASSED' if res['passed'] else 'FAILED'}")
    print(f"Port: {res['port']}")
    for d in res["details"]:
        print(d)
    if res["errors"]:
        print(f"\nErrors: {res['errors']}")
