from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ACCESS_KEY = "peas-access"
DEFAULT_SECRET_KEY = "peas-secret"
AZURE_ACCOUNT = "devstoreaccount1"


@dataclass(frozen=True)
class PeasSettings:
    api_url: str
    ui_url: str
    access_key_id: str
    secret_access_key: str
    azure_account: str
    storage_dir: Path | None
    enabled_providers: frozenset[str]

    def require_provider(self, provider: str) -> None:
        if provider not in self.enabled_providers:
            pytest.skip(f"{provider} SDK tests disabled by PEAS_SDK_PROVIDERS")

    def bucket_name(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:16]}".lower()


def _providers_from_env() -> frozenset[str]:
    raw = os.getenv("PEAS_SDK_PROVIDERS", "s3,azure,gcs,oci")
    providers = {provider.strip().lower() for provider in raw.split(",") if provider.strip()}
    aliases = {
        "s3-family": "s3",
        "azure-blob": "azure",
        "oci-object": "oci",
    }
    normalized = {aliases.get(provider, provider) for provider in providers}
    return frozenset(normalized)


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_health(api_url: str, process: subprocess.Popen[str] | None = None) -> None:
    deadline = time.monotonic() + 30
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError(f"PEAS exited before /healthz became ready:\n{output}")
        try:
            with urllib.request.urlopen(f"{api_url}/healthz", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"PEAS /healthz did not become ready at {api_url}: {last_error}")


def _binary_path() -> Path:
    configured = os.getenv("PEAS_BINARY")
    if configured:
        return Path(configured)
    return REPO_ROOT / "target" / "debug" / "peas-emulator"


def _ensure_binary() -> Path:
    binary = _binary_path()
    if binary.exists():
        return binary
    subprocess.run(
        ["cargo", "build", "--bin", "peas-emulator"],
        cwd=REPO_ROOT,
        check=True,
    )
    return binary


@pytest.fixture(scope="session")
def peas_server() -> PeasSettings:
    api_url = os.getenv("PEAS_API_URL")
    enabled_providers = _providers_from_env()
    if api_url:
        yield PeasSettings(
            api_url=api_url.rstrip("/"),
            ui_url=os.getenv("PEAS_UI_URL", "").rstrip("/"),
            access_key_id=os.getenv("PEAS_ACCESS_KEY_ID", DEFAULT_ACCESS_KEY),
            secret_access_key=os.getenv("PEAS_SECRET_ACCESS_KEY", DEFAULT_SECRET_KEY),
            azure_account=os.getenv("PEAS_AZURE_ACCOUNT", AZURE_ACCOUNT),
            storage_dir=None,
            enabled_providers=enabled_providers,
        )
        return

    api_port = _reserve_port()
    ui_port = _reserve_port()
    storage_dir = Path(tempfile.mkdtemp(prefix="peas-sdk-storage-"))
    binary = _ensure_binary()
    env = os.environ.copy()
    env.update(
        {
            "API_PORT": str(api_port),
            "UI_PORT": str(ui_port),
            "BLOBS_PATH": str(storage_dir),
            "ADMIN_AUTH_DISABLED": "true",
            "RUST_LOG": env.get("RUST_LOG", "peas_emulator=info"),
        }
    )
    if os.getenv("PEAS_SDK_ENFORCE_AUTH") == "1":
        env["ACCESS_KEY_ID"] = DEFAULT_ACCESS_KEY
        env["SECRET_ACCESS_KEY"] = DEFAULT_SECRET_KEY
    else:
        env.pop("ACCESS_KEY_ID", None)
        env.pop("SECRET_ACCESS_KEY", None)

    process = subprocess.Popen(
        [str(binary)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    settings = PeasSettings(
        api_url=f"http://127.0.0.1:{api_port}",
        ui_url=f"http://127.0.0.1:{ui_port}",
        access_key_id=DEFAULT_ACCESS_KEY,
        secret_access_key=DEFAULT_SECRET_KEY,
        azure_account=AZURE_ACCOUNT,
        storage_dir=storage_dir,
        enabled_providers=enabled_providers,
    )

    try:
        _wait_for_health(settings.api_url, process)
        yield settings
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(storage_dir, ignore_errors=True)
