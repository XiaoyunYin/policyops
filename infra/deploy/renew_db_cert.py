"""Host maintenance in the app image: renew the isolated PostgreSQL certificate, retaining its key."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


directory = Path("/secrets")
key = serialization.load_pem_private_key((directory / "postgres_tls_key").read_bytes(), password=None)
if not isinstance(key, rsa.RSAPrivateKey):
    raise ValueError("expected the Compose RSA key")
old = x509.load_pem_x509_certificate((directory / "postgres_tls_cert").read_bytes())
now = datetime.now(UTC)
cert = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("postgres")]), critical=False)
        .sign(key, hashes.SHA256()))
# Write the existing inode: Compose file-secret bind mounts must continue seeing it.
(directory / "postgres_tls_cert").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(directory / "postgres_tls_cert").chmod(0o444)
