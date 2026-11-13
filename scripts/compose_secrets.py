"""Create fresh Compose secrets under POLICYOPS_TEMP_DIR, outside the checkout; never print values.

Use the frozen application Python environment (cryptography is an existing dependency).
Files are read-only to containers; the host directory is private (0700 or a Windows user-only ACL).
Refuse an existing target, including partial generations: rotation is an explicit new-volume operation.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import getpass
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
NAMES = ("postgres", "policyops_app_migrator", "policyops_auth_runtime", "policyops_app_runtime",
         "policyops_eval_runtime", "policyops_worker_discovery", "retail_migrator", "retail_runtime",
         "retail_key", "client_secret", "alice", "bob", "carol")


def external_directory(raw: str, temp: str) -> Path:
    path, base = Path(raw), Path(temp)
    if not path.is_absolute() or not base.is_absolute():
        raise ValueError("secrets and temporary directories must be absolute")
    path, base = path.resolve(), base.resolve()
    if path == ROOT or ROOT in path.parents or base == ROOT or ROOT in base.parents:
        raise ValueError("secrets and temporary directories must be outside the checkout")
    if base not in path.parents:
        raise ValueError("secrets must be in a task-specific subdirectory of POLICYOPS_TEMP_DIR")
    return path


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    if os.name == "nt":
        user = getpass.getuser()
        domain = os.environ.get("USERDOMAIN")
        identity = f"{domain}\\{user}" if domain else user
        done = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(OI)(CI)F"],
                              capture_output=True, check=False)
        if done.returncode:
            raise OSError("could not restrict the secrets directory ACL")
    else:
        path.chmod(0o700)


def generate(path: Path, run_id: str) -> list[str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_directory(path)
    names = [*NAMES, "postgres_tls_key", "postgres_tls_cert"]
    (path / "owner.json").write_text(json.dumps({"run_id": run_id, "files": names}) + "\n", encoding="utf-8")
    for name in NAMES:
        (path / name).write_bytes(secrets.token_urlsafe(48).encode("ascii"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PolicyOps fictional local PostgreSQL")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("postgres")]), critical=False)
        .sign(key, hashes.SHA256()))
    (path / "postgres_tls_key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (path / "postgres_tls_cert").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    for name in names:
        # Directory ACL/mode protects host access. Compose's file source mounts ignore uid/gid/mode
        # on some platforms, so each explicitly mounted file must be readable by its numeric container UID.
        (path / name).chmod(0o444)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=os.environ.get("POLICYOPS_RUN_ID"))
    args = parser.parse_args()
    try:
        if not args.run_id:
            raise ValueError("POLICYOPS_RUN_ID is required")
        target = external_directory(os.environ["POLICYOPS_SECRETS_DIR"], os.environ["POLICYOPS_TEMP_DIR"])
        names = generate(target, args.run_id)
    except (KeyError, OSError, ValueError, ImportError) as error:
        print(f"Secrets generation failed ({type(error).__name__}); values omitted.", file=sys.stderr)
        return 1
    print(f"Created {len(names)} secret files in the configured external directory; values omitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
