"""Host maintenance in the app image: renew the isolated PostgreSQL certificate, retaining its key."""

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


directory = Path("/secrets")
certificate = directory / "postgres_tls_cert"
key = serialization.load_pem_private_key((directory / "postgres_tls_key").read_bytes(), password=None)
if not isinstance(key, rsa.RSAPrivateKey):
    raise ValueError("expected the Compose RSA key")
old = x509.load_pem_x509_certificate(certificate.read_bytes())
now = datetime.now(UTC)
cert = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("postgres")]), critical=False)
        .sign(key, hashes.SHA256()))
# Reset recreates the containers after renewal, so their secret mounts see the new inode.
metadata = certificate.stat()
staged_path = None
try:
    with NamedTemporaryFile(dir=directory, prefix=f".{certificate.name}.", delete=False) as staged:
        staged_path = Path(staged.name)
        staged.write(cert.public_bytes(serialization.Encoding.PEM))
        staged.flush()
        os.fchown(staged.fileno(), metadata.st_uid, metadata.st_gid)
        os.fchmod(staged.fileno(), stat.S_IMODE(metadata.st_mode))
        os.fsync(staged.fileno())
    os.replace(staged_path, certificate)  # noqa: PTH105
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if staged_path is not None:
        staged_path.unlink(missing_ok=True)
