"""Run the local SignalRoom demo from startup through alert creation."""

from __future__ import annotations

import argparse
import os
import random
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Optional
from uuid import uuid4

import httpx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8003
UI_HOST = "127.0.0.1"
UI_PORT = 8501
STARTUP_TIMEOUT_SECONDS = 30.0

RELEVANT_MESSAGE = (
    "Sicily",
    "I am traveling today and expect to connect through the company VPN. "
    "I have not approved any privileged access changes in chat.",
)

BACKGROUND_MESSAGES = (
    ("Eitan", "The security review starts at 3 PM; please add notes to the agenda."),
    ("Haden", "The production maintenance window begins later this afternoon."),
    ("Reuben", "The staging health checks are green after this morning's deploy."),
    ("Eitan", "Reminder: never paste credentials or access tokens into this channel."),
    ("Haden", "I am checking the firewall telemetry for unexpected retry patterns."),
    ("Reuben", "The database backup completed successfully."),
    ("Eitan", "Does anyone recognize the new VPN source address in the alert feed?"),
    ("Haden", "HTTPS traffic to the protected demo server should remain default-deny."),
)


def _is_healthy(url: str) -> bool:
    try:
        response = httpx.get(url, timeout=1.0)
        return response.status_code == 200
    except httpx.RequestError:
        return False


def _wait_until_healthy(
    url: str,
    *,
    label: str,
    process: Optional[subprocess.Popen[bytes]] = None,
) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _is_healthy(url):
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(
                f"{label} exited during startup with status {process.returncode}."
            )
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {label} at {url}.")


def _start_backend(backend_url: str) -> Optional[subprocess.Popen[bytes]]:
    health_url = f"{backend_url}/health"
    if _is_healthy(health_url):
        print(f"[demo] Reusing backend at {backend_url}.", flush=True)
        return None

    print(f"[demo] Starting FastAPI backend at {backend_url}...", flush=True)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend:app",
            "--host",
            BACKEND_HOST,
            "--port",
            str(BACKEND_PORT),
        ],
        cwd=PROJECT_ROOT,
    )
    _wait_until_healthy(health_url, label="FastAPI backend", process=process)
    return process


def _seed_demo(backend_url: str, message_count: int, seed: Optional[int]) -> dict:
    randomizer = random.Random(seed) if seed is not None else random.SystemRandom()
    background_count = min(max(message_count - 1, 0), len(BACKGROUND_MESSAGES))
    messages = [RELEVANT_MESSAGE]
    messages.extend(randomizer.sample(BACKGROUND_MESSAGES, background_count))

    with httpx.Client(base_url=backend_url, timeout=25.0) as client:
        print(f"[demo] Posting {len(messages)} workplace messages...", flush=True)
        for author, content in messages:
            response = client.post(
                "/messages",
                json={"author": author, "content": content},
            )
            response.raise_for_status()

        alert_id = f"automatic-demo-{uuid4().hex[:10]}"
        print(f"[demo] Sending network alert {alert_id}...", flush=True)
        response = client.post(
            "/network-alerts",
            json={
                "alert_id": alert_id,
                "actor": "Sicily",
                "request_summary": (
                    "grant temporary HTTPS access from 10.0.2.1 to "
                    "10.0.3.10:443/tcp"
                ),
                "target_resource": "protected demo server at 10.0.3.10",
                "source_ip": "10.0.2.1",
                "network_risk_score": 0.94,
            },
        )
        response.raise_for_status()
        return response.json()


def _start_ui(backend_url: str, ui_url: str) -> Optional[subprocess.Popen[bytes]]:
    health_url = f"{ui_url}/_stcore/health"
    if _is_healthy(health_url):
        print(f"[demo] Reusing Streamlit UI at {ui_url}.", flush=True)
        return None

    print(f"[demo] Starting Streamlit UI at {ui_url}...", flush=True)
    environment = os.environ.copy()
    environment["BACKEND_URL"] = backend_url
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            "ui.py",
            "--server.address",
            UI_HOST,
            "--server.port",
            str(UI_PORT),
            "--server.headless",
            "true",
            "--browser.gatherUsageStats",
            "false",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
    )
    _wait_until_healthy(health_url, label="Streamlit UI", process=process)
    return process


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Start SignalRoom, seed workplace chat, create a security alert, "
            "and keep the demo services running."
        )
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=6,
        choices=range(1, len(BACKGROUND_MESSAGES) + 2),
        metavar=f"1-{len(BACKGROUND_MESSAGES) + 1}",
        help="number of demo messages to post (default: 6)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="optional seed for repeatable background-message selection",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="exit after setup instead of waiting for Ctrl+C",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not try to open the Streamlit UI in the default browser",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}"
    ui_url = f"http://{UI_HOST}:{UI_PORT}"
    owned_processes: list[subprocess.Popen[bytes]] = []

    try:
        backend = _start_backend(backend_url)
        if backend is not None:
            owned_processes.append(backend)

        event = _seed_demo(backend_url, args.messages, args.seed)
        ui = _start_ui(backend_url, ui_url)
        if ui is not None:
            owned_processes.append(ui)

        context = event.get("ai_context") or {}
        print("", flush=True)
        print("[demo] Demo is ready.", flush=True)
        print(f"[demo] UI: {ui_url}", flush=True)
        print(f"[demo] API docs: {backend_url}/docs", flush=True)
        print(f"[demo] Security event: {event.get('id')}", flush=True)
        print(
            "[demo] AI context status: "
            f"{context.get('context_status', event.get('analysis_status'))}",
            flush=True,
        )
        print(
            "[demo] Switch the UI identity to Sicily and answer Yes, No, or Unsure.",
            flush=True,
        )

        if args.no_wait:
            return 0

        if not args.no_browser and not webbrowser.open(ui_url):
            print(f"[demo] Open {ui_url} in your browser.", flush=True)

        print("[demo] Press Ctrl+C to stop services started by this script.", flush=True)
        while True:
            for process in owned_processes:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"A demo service exited unexpectedly with status {process.returncode}."
                    )
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[demo] Stopping demo services...", flush=True)
        return 0
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"[demo] Error: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        for process in reversed(owned_processes):
            _stop_process(process)


if __name__ == "__main__":
    raise SystemExit(main())
