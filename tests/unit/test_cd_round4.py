"""Offline regressions for certificate renewal and reset adoption."""

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import runpy
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from infra.deploy import cd_agent as cd
from tests.unit.test_cd_agent import IMAGES, A, B
from tests.unit.test_cd_agent import agent as agent
from tests.unit.test_cd_round2 import host as host
from tests.unit.test_cd_round2 import run_host_script
from tests.unit.test_cd_round3 import RESET_DAY


@pytest.mark.parametrize("interrupt_at", ["file", "directory"])
def test_certificate_renewal_survives_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupt_at: str,
) -> None:
    directory = tmp_path / "secrets"
    directory.mkdir()
    certificate = directory / "postgres_tls_cert"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (directory / "postgres_tls_key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "postgres")])
    now = datetime.now(UTC)
    original = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + timedelta(days=1))
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    certificate.write_bytes(original)
    certificate.chmod(0o640)
    metadata = certificate.stat()
    source = Path(__file__).resolve().parents[2] / "infra/deploy/renew_db_cert.py"
    script = tmp_path / source.name
    script.write_text(source.read_text(encoding="utf-8").replace('"/secrets"', repr(str(directory))),
                      encoding="utf-8")

    events: list[str] = []
    interrupted = False
    directory_fd = -1
    real_open, real_fsync, real_replace = os.open, os.fsync, os.replace
    real_fchown = getattr(os, "fchown", None)
    real_fchmod = getattr(os, "fchmod", None)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    def open_file(path: str | Path, flags: int, mode: int = 0o777) -> int:
        nonlocal directory_fd
        if path != directory:
            return real_open(path, flags, mode)
        assert flags == os.O_RDONLY | directory_flag
        directory_fd = real_open(directory if os.name == "posix" else os.devnull, flags)
        return directory_fd

    def set_owner(fd: int, uid: int, gid: int) -> None:
        assert (uid, gid) == (metadata.st_uid, metadata.st_gid)
        assert os.fstat(fd).st_ino != certificate.stat().st_ino
        if real_fchown is not None:
            real_fchown(fd, uid, gid)
        events.append("owner")

    def set_mode(fd: int, mode: int) -> None:
        assert mode == stat.S_IMODE(metadata.st_mode)
        if real_fchmod is not None:
            real_fchmod(fd, mode)
        events.append("mode")

    def sync(fd: int) -> None:
        nonlocal interrupted
        stage = "directory" if fd == directory_fd else "file"
        events.append(stage)
        if stage == interrupt_at and not interrupted:
            interrupted = True
            raise OSError("interrupted")
        if stage == "file" or os.name == "posix":
            real_fsync(fd)

    def replace(src: Path, dst: Path) -> None:
        staged = Path(src)
        assert staged.parent == directory and staged != dst == certificate
        assert x509.load_pem_x509_certificate(staged.read_bytes()).serial_number != 1
        events.append("replace")
        real_replace(src, dst)

    with monkeypatch.context() as patch:
        patch.setattr(os, "O_DIRECTORY", directory_flag, raising=False)
        patch.setattr(os, "open", open_file)
        patch.setattr(os, "fchown", set_owner, raising=False)
        patch.setattr(os, "fchmod", set_mode, raising=False)
        patch.setattr(os, "fsync", sync)
        patch.setattr(os, "replace", replace)
        with pytest.raises(OSError, match="interrupted"):
            runpy.run_path(str(script))
        after_interrupt = certificate.read_bytes()
        x509.load_pem_x509_certificate(after_interrupt)
        assert (after_interrupt == original) == (interrupt_at == "file")
        events.clear()
        directory_fd = -1
        runpy.run_path(str(script))

    assert events == ["owner", "mode", "file", "replace", "directory"]
    renewed = x509.load_pem_x509_certificate(certificate.read_bytes())
    assert renewed.subject == name and renewed.serial_number != 1
    assert certificate.read_bytes() != after_interrupt
    final = certificate.stat()
    assert (final.st_uid, final.st_gid, final.st_mode) == (metadata.st_uid, metadata.st_gid, metadata.st_mode)
    assert not list(directory.glob(".postgres_tls_cert.*"))


def test_reset_before_first_adopt_selects_nightly_fixture(host: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    records = host / "cd"
    (records / "state.json").unlink()
    records.rmdir()

    result, _ = run_host_script(host, "reset.sh")
    assert result.returncode == 0, result.stderr
    pending = records / "reset-pending"
    assert pending.is_file()
    assert pending.read_text(encoding="ascii").split() == [RESET_DAY, A]
    assert not (records / "state.json").exists()
    if os.name == "posix":
        assert stat.S_IMODE(records.stat().st_mode) == 0o700

    for name in ("policyops-cd", "deploy.sh", "deploy_verify.py"):
        (host / name).touch()
    controller = cd.Agent(host, host, 9)
    nightly = host / "logs" / "scenario-nightly.json"
    monkeypatch.setattr(controller, "current", lambda: A)
    monkeypatch.setattr(controller, "image_ids", lambda *_: IMAGES.copy())
    monkeypatch.setattr(controller, "retain_adopted", lambda _: None)
    monkeypatch.setattr(controller, "gate", lambda _sha, _images, seed, *_: seed == nightly and seed.is_file())
    assert controller.operator("adopt", "") == 0
    assert cd.load_state(controller.state_path)["gated_fixture"] == {"release": A, "seed_path": str(nightly)}
    assert not pending.exists()


@pytest.mark.parametrize("reset_release", [A, B])
def test_adopt_refuses_unfinished_reset(agent: cd.Agent, monkeypatch: pytest.MonkeyPatch, reset_release: str) -> None:
    progress = agent.cd / "reset-progress"
    progress.write_text(f"{RESET_DAY} {reset_release} seeded\n", encoding="ascii")
    (agent.cd / "reset-pending").write_text(f"{RESET_DAY} {reset_release}\n", encoding="ascii")
    original = agent.state_path.read_bytes()
    monkeypatch.setattr(agent, "gate", lambda *_: True)

    with pytest.raises(cd.Stop, match=r"^reset_in_progress$"):
        agent.operator("adopt", "")
    assert progress.exists() and agent.state_path.read_bytes() == original


def test_reset_retry_finishes_after_pending_was_published(host: Path) -> None:
    records = host / "cd"
    pending = records / "reset-pending"
    progress = records / "reset-progress"
    completed = records / "reset-completed"
    completed.mkdir()
    record = f"{RESET_DAY} {A}\n"
    progress.write_text(record.rstrip() + " seeded\n", encoding="ascii", newline="\n")
    pending.write_text(record, encoding="ascii", newline="\n")
    (completed / RESET_DAY).write_text(record, encoding="ascii", newline="\n")

    result, trace = run_host_script(host, "reset.sh")
    assert result.returncode == 0, result.stderr
    assert not progress.exists() and pending.read_text(encoding="ascii") == record
    assert not any(line.startswith("docker ") for line in trace)
