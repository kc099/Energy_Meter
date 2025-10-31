#!/usr/bin/env python3
"""Gas monitor Python client mirroring the energy-meter flow with AES-GCM encryption."""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _env_int(name: str) -> int | None:
    value = os.getenv(name)
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        print(f"[config] Ignoring non-numeric value for {name}", file=sys.stderr)
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision a gas monitor device and push encrypted telemetry to the Django API.",
    )
    parser.add_argument("--host", default=os.getenv("GM_HOST", "localhost"), help="API host without protocol")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("GM_PORT", 8000)),
        help="API port number",
    )
    parser.add_argument("--no-tls", action="store_true", help="Use HTTP instead of HTTPS (development only)")
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.getenv("GM_STATE_FILE", "gas_monitor_client_state.json")),
        help="Where API keys and AES keys are cached",
    )
    parser.add_argument(
        "--telemetry-interval",
        type=float,
        default=float(os.getenv("GM_TELEMETRY_INTERVAL", 2.0)),
        help="Seconds between telemetry frames",
    )
    parser.add_argument(
        "--provisioning-token",
        help="Optional provisioning token override; stored for future runs",
    )
    parser.add_argument(
        "--monitor-id",
        type=int,
        default=_env_int("GM_MONITOR_ID"),
        help="Fallback gas monitor ID if state file lacks one",
    )
    parser.add_argument("--once", action="store_true", help="Send a single telemetry frame instead of looping")
    parser.add_argument(
        "--min-level",
        type=float,
        default=float(os.getenv("GM_MIN_LEVEL", 10.0)),
        help="Lower bound (inclusive) for synthetic gas level generation",
    )
    parser.add_argument(
        "--max-level",
        type=float,
        default=float(os.getenv("GM_MAX_LEVEL", 140.0)),
        help="Upper bound (inclusive) for synthetic gas level generation",
    )
    parser.add_argument(
        "--unit",
        default=os.getenv("GM_UNIT", "ppm"),
        help="Measurement unit reported with telemetry",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("GM_TIMEOUT", 15.0)),
        help="HTTP request timeout in seconds",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print payloads and responses for debugging",
    )
    return parser.parse_args()


@dataclass
class ClientConfig:
    host: str
    port: int
    use_tls: bool
    state_file: Path
    telemetry_interval: float
    monitor_id: int | None
    min_level: float
    max_level: float
    unit: str
    once: bool
    timeout: float
    verbose: bool


# ------------------------------- state handling --------------------------------

def load_state(path: Path) -> Dict[str, str]:
    if path.exists():
        state = json.loads(path.read_text())
    else:
        state = {}

    state.setdefault("api_key", "")
    state.setdefault("provisioning_token", "")
    state.setdefault("aes_key_b64", "")
    state.setdefault("monitor_id", None)
    state.setdefault("telemetry_url", "")
    return state


def save_state(path: Path, state: Dict[str, str]) -> None:
    path.write_text(json.dumps(state, indent=2))


# --------------------------- encryption primitives -----------------------------

def resolve_aes_key_bytes(state: Dict[str, str]) -> bytes:
    key_b64 = state.get("aes_key_b64", "")
    if not key_b64:
        raise RuntimeError("No AES key found in local state; re-run provisioning.")
    try:
        key = base64.b64decode(key_b64)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise RuntimeError("Stored AES key is not valid Base64") from exc
    if len(key) not in (16, 24, 32):
        raise RuntimeError("Stored AES key has unexpected length")
    return key


def encrypt_payload(payload: Dict[str, float], aes_key: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(payload).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "algorithm": "AESGCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


# ---------------------------- HTTP helper routines -----------------------------

def build_base_url(cfg: ClientConfig) -> str:
    scheme = "https" if cfg.use_tls else "http"
    return f"{scheme}://{cfg.host}:{cfg.port}"


def claim_token(session: requests.Session, cfg: ClientConfig, state: Dict[str, str]) -> None:
    token = state.get("provisioning_token")
    if not token:
        print("[claim] No provisioning token present; skipping claim request")
        return

    url = build_base_url(cfg) + "/api/devices/claim"
    print(f"[claim] Claiming token against {url}")
    response = session.post(url, json={"token": token}, timeout=cfg.timeout)

    if response.status_code not in (200, 201):
        raise RuntimeError(f"Provisioning failed: {response.status_code} {response.text}")

    data = response.json()
    api_key = data.get("api_key")
    encryption_key = data.get("encryption_key_b64")
    monitor_id = data.get("gas_monitor_id")
    if not api_key:
        raise RuntimeError("Claim response missing api_key")
    if not encryption_key:
        raise RuntimeError("Claim response missing encryption key")
    if monitor_id is None:
        raise RuntimeError("Claim response missing gas monitor identifier")

    ingest_url = data.get("ingest_url", "")

    state["api_key"] = api_key
    state["provisioning_token"] = ""
    state["aes_key_b64"] = encryption_key
    state["monitor_id"] = int(monitor_id)
    state["telemetry_url"] = ingest_url if "gas_monitor" in ingest_url else ""
    save_state(cfg.state_file, state)
    print("[claim] API key + AES key stored locally; provisioning token cleared")

    if ingest_url:
        print(f"[claim] Ingest URL provided by server: {ingest_url}")


def build_telemetry_payload(cfg: ClientConfig) -> Dict[str, float | str]:
    value = random.uniform(cfg.min_level, cfg.max_level)
    return {
        "gas_level": round(value, 3),
        "unit": cfg.unit,
    }


def _resolve_monitor_id(cfg: ClientConfig, state: Dict[str, str]) -> int:
    candidate = state.get("monitor_id")
    if candidate in (None, "") and cfg.monitor_id is not None:
        candidate = cfg.monitor_id
        state["monitor_id"] = candidate
        save_state(cfg.state_file, state)

    if candidate in (None, ""):
        raise RuntimeError(
            "Monitor identifier missing. Re-run provisioning or pass --monitor-id."
        )

    try:
        monitor_id = int(candidate)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Stored monitor identifier is not a valid integer") from exc

    if state.get("monitor_id") != monitor_id:
        state["monitor_id"] = monitor_id
        save_state(cfg.state_file, state)

    return monitor_id


def _resolve_telemetry_url(cfg: ClientConfig, state: Dict[str, str], monitor_id: int) -> str:
    telemetry_url = state.get("telemetry_url") or ""
    if telemetry_url:
        return telemetry_url

    telemetry_url = build_base_url(cfg) + f"/gas_monitor/api/devices/{monitor_id}/telemetry/"
    state["telemetry_url"] = telemetry_url
    save_state(cfg.state_file, state)
    return telemetry_url


def send_telemetry(session: requests.Session, cfg: ClientConfig, state: Dict[str, str]) -> None:
    api_key = state.get("api_key")
    if not api_key:
        print("[telemetry] Missing API key; cannot post data")
        return

    monitor_id = _resolve_monitor_id(cfg, state)
    url = _resolve_telemetry_url(cfg, state, monitor_id)

    telemetry = build_telemetry_payload(cfg)
    aes_key = resolve_aes_key_bytes(state)
    envelope = encrypt_payload(telemetry, aes_key)

    headers = {"Authorization": f"Bearer {api_key}"}

    if cfg.verbose:
        print(f"[telemetry] POST {url}")
        print(json.dumps({"decrypted": telemetry, "envelope": envelope}, indent=2))

    response = session.post(url, json=envelope, headers=headers, timeout=cfg.timeout)

    if response.status_code == 401:
        state["api_key"] = ""
        save_state(cfg.state_file, state)
        raise RuntimeError("Server rejected API key; deleted cached key")

    if response.status_code == 404:
        state["telemetry_url"] = ""
        save_state(cfg.state_file, state)
    if response.status_code // 100 != 2:
        raise RuntimeError(f"Telemetry push failed: {response.status_code} {response.text}")

    if cfg.verbose:
        print(f"[telemetry] Acknowledged: {response.status_code} -> {response.text}")
    else:
        print("[telemetry] Frame sent")


# ----------------------------------- main --------------------------------------

def main() -> int:
    args = parse_args()

    if args.max_level <= args.min_level:
        print("[config] --max-level must be greater than --min-level", file=sys.stderr)
        return 1

    cfg = ClientConfig(
        host=args.host,
        port=args.port,
        use_tls=not args.no_tls,
        state_file=args.state_file,
        telemetry_interval=args.telemetry_interval,
        monitor_id=args.monitor_id,
        min_level=args.min_level,
        max_level=args.max_level,
        unit=args.unit,
        once=args.once,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    state = load_state(cfg.state_file)
    if args.provisioning_token:
        state["provisioning_token"] = args.provisioning_token.strip()
        save_state(cfg.state_file, state)

    session = requests.Session()

    try:
        while True:
            try:
                needs_claim = bool(state.get("provisioning_token")) or not state.get("api_key")
                if needs_claim:
                    claim_token(session, cfg, state)
                send_telemetry(session, cfg, state)
            except Exception as exc:
                print(f"[error] {exc}")
            finally:
                if cfg.once:
                    break
                time.sleep(cfg.telemetry_interval)
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
