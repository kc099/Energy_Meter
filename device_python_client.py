#!/usr/bin/env python3
"""Energy Meter Python client that mirrors the Arduino reference flow and adds AES-GCM encryption."""

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

# ---------------------------- configuration helpers ----------------------------
# This block parses CLI / env configuration so the script is portable and easy to tune.

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision a device and push encrypted telemetry to the Django API."
    )
    parser.add_argument("--host", default=os.getenv("EM_HOST", "localhost"), help="API host without protocol")
    parser.add_argument("--port", type=int, default=int(os.getenv("EM_PORT", 8000)), help="API port number")
    parser.add_argument("--no-tls", action="store_true", help="Use HTTP instead of HTTPS (development only)")
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(os.getenv("EM_STATE_FILE", "device_client_state.json")),
        help="Where API/provisioning tokens are cached",
    )
    parser.add_argument(
        "--telemetry-interval",
        type=float,
        default=float(os.getenv("EM_TELEMETRY_INTERVAL", 0.02)),
        help="Seconds between telemetry frames",
    )
    parser.add_argument(
        "--provisioning-token",
        help="Optional provisioning token override; stored after first successful run",
    )
    parser.add_argument("--once", action="store_true", help="Send a single telemetry frame instead of looping")
    return parser.parse_args()


@dataclass
class ClientConfig:
    """Runtime configuration for the client."""

    host: str
    port: int
    use_tls: bool
    state_file: Path
    telemetry_interval: float


# ------------------------------- state handling --------------------------------
# This block loads/saves API keys and provisioning tokens so devices survive reboots.

def load_state(path: Path) -> Dict[str, str]:
    if path.exists():
        return json.loads(path.read_text())
    return {"api_key": "", "provisioning_token": "", "aes_key_b64": ""}


def save_state(path: Path, state: Dict[str, str]) -> None:
    path.write_text(json.dumps(state, indent=2))


# --------------------------- encryption primitives -----------------------------
# This block wraps AES-GCM so the rest of the client just passes JSON dictionaries.

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
# This block centralizes networking so TLS, headers, and error handling stay consistent.

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
    response = session.post(url, json={"token": token}, timeout=15)

    if response.status_code not in (200, 201):
        raise RuntimeError(f"Provisioning failed: {response.status_code} {response.text}")

    data = response.json()
    api_key = data.get("api_key")
    encryption_key = data.get("encryption_key_b64")
    if not api_key:
        raise RuntimeError("Claim response missing api_key")
    if not encryption_key:
        raise RuntimeError("Claim response missing encryption key")

    state["api_key"] = api_key
    state["provisioning_token"] = ""
    state["aes_key_b64"] = encryption_key
    save_state(cfg.state_file, state)
    print("[claim] API + AES keys stored locally; provisioning token cleared")


def send_telemetry(session: requests.Session, cfg: ClientConfig, state: Dict[str, str]) -> None:
    api_key = state.get("api_key")
    if not api_key:
        print("[telemetry] Missing API key; cannot post data")
        return

    telemetry = {
        "voltage": random.uniform(220.0, 240.0),
        "current": random.uniform(1.0, 20.0),
        "power_factor": random.uniform(0.8, 1.0),
        "kwh": random.uniform(1000.0, 2000.0),
    }
    aes_key = resolve_aes_key_bytes(state)
    envelope = encrypt_payload(telemetry, aes_key)

    url = build_base_url(cfg) + "/api/device-data/ingest"
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"[telemetry] Sending encrypted payload to {url}")
    response = session.post(url, json=envelope, headers=headers, timeout=15)

    if response.status_code == 401:
        state["api_key"] = ""
        save_state(cfg.state_file, state)
        raise RuntimeError("Server rejected API key; deleted cached key")

    if response.status_code // 100 != 2:
        raise RuntimeError(f"Telemetry push failed: {response.status_code} {response.text}")

    print(f"[telemetry] Frame acknowledged: {response.status_code}")


# ----------------------------------- main --------------------------------------
# This block wires everything together: load state, claim if needed, send telemetry in a loop.

def main() -> int:
    args = parse_args()
    cfg = ClientConfig(
        host=args.host,
        port=args.port,
        use_tls=not args.no_tls,
        state_file=args.state_file,
        telemetry_interval=args.telemetry_interval,
    )

    state = load_state(cfg.state_file)
    if args.provisioning_token:
        state["provisioning_token"] = args.provisioning_token.strip()
        save_state(cfg.state_file, state)

    session = requests.Session()

    while True:
        try:
            if not state.get("api_key"):
                claim_token(session, cfg, state)
            send_telemetry(session, cfg, state)
        except Exception as exc:
            print(f"[error] {exc}")
        finally:
            if args.once:
                break
            time.sleep(cfg.telemetry_interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
