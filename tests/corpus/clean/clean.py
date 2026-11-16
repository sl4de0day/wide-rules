import hashlib
import hmac
import os
import secrets
import subprocess
import yaml


def load_yaml_config(raw_yaml: str):
    return yaml.safe_load(raw_yaml)


def fetch_user_orders(cursor, user_id: int, status: str):
    cursor.execute(
        "SELECT id, total_cents FROM orders WHERE user_id = %s AND status = %s",
        (user_id, status),
    )
    return cursor.fetchall()


def safe_resolve_path(base_dir: str, rel_path: str) -> str:
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, rel_path))
    if os.path.commonpath([base, target]) != base:
        raise ValueError("Path escapes base directory")
    return target


def run_git_status(workspace_root: str) -> str:
    completed = subprocess.run(
        ["git", "status", "--short"],
        cwd=workspace_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


def verify_digest(expected_hex: str, payload: bytes, secret: bytes) -> bool:
    computed = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_hex)
