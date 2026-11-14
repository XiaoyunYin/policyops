"""scripts/fetch_tokenizer_vocab.py (T12): one pinned URL and digest, a bounded read, a contained destination outside
the checkout that refuses links (real Windows junctions or POSIX symlinks), unique exclusive partial files and an
atomic, hash-checked install. No network: the download is replaced by a local reader. The escape tests point their
links into a *fake* checkout under the temporary root, never the real one."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import threading
from typing import Any
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "fetch_tokenizer_vocab.py"
_spec = importlib.util.spec_from_file_location("policyops_fetch_tokenizer_vocab", SCRIPT)
assert _spec is not None and _spec.loader is not None
vocab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vocab)
DATA = b"YQ== 0\n"


def link_directory(link: Path, target: Path) -> None:
    """A directory link: a real junction on Windows (no privilege needed), a symlink elsewhere."""
    if sys.platform == "win32":  # mypy narrows platform-only APIs on this check
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


class FetchTokenizerVocabTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="policyops-vocab-", dir=os.environ.get("POLICYOPS_TEMP_DIR"))
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root = base / "temp-root"
        self.root.mkdir()
        self.env = {"POLICYOPS_TEMP_DIR": str(self.root)}
        self.target = self.root / "tokenizers" / "cl100k_base.tiktoken"
        self.fake_checkout = base / "fake-checkout"
        (self.fake_checkout / "ingress").mkdir(parents=True)
        self.elsewhere = base / "elsewhere"
        self.elsewhere.mkdir()
        pinned = mock.patch.object(vocab, "SHA256", hashlib.sha256(DATA).hexdigest())
        pinned.start()
        self.addCleanup(pinned.stop)

    def source(self, data: bytes = DATA) -> Path:
        path = self.root.parent / "downloaded"
        path.write_bytes(data)
        return path

    def partials(self) -> list[str]:
        return sorted(p.name for p in self.target.parent.iterdir() if p.name.endswith(".partial"))

    def test_the_pin_is_the_one_official_file(self) -> None:
        self.assertEqual(vocab.URL, "https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken")
        self.assertEqual(vocab.MAX_BYTES, 2 << 20)
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('SHA256 = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"', source)

    def test_a_verified_copy_is_installed_atomically_and_idempotently(self) -> None:
        self.assertEqual(vocab.main(["--from-file", str(self.source())], self.env), 0)
        self.assertEqual(self.target.read_bytes(), DATA)
        self.assertEqual(self.partials(), [])
        with mock.patch.object(vocab, "download", side_effect=AssertionError("must not download")):
            self.assertEqual(vocab.main([], self.env), 0)  # already provisioned: nothing fetched

    def test_a_different_or_oversized_file_is_never_written(self) -> None:
        self.assertEqual(vocab.main(["--from-file", str(self.source(b"not the vocabulary"))], self.env), 1)
        self.assertEqual(vocab.main(["--from-file", str(self.source(b"a" * (vocab.MAX_BYTES + 1)))], self.env), 1)
        self.assertFalse(self.target.exists())

    def test_the_download_reads_only_the_pinned_url_and_is_bounded(self) -> None:
        opened: list[str] = []

        def urlopen(url: str, timeout: float) -> Any:
            opened.append(url)
            return io.BytesIO(DATA)

        with mock.patch.object(vocab.urllib.request, "urlopen", urlopen):
            self.assertEqual(vocab.main([], self.env), 0)
        self.assertEqual(opened, [vocab.URL])
        oversized = io.BytesIO(b"a" * (vocab.MAX_BYTES + 1))
        with (mock.patch.object(vocab.urllib.request, "urlopen", lambda url, timeout: oversized),
              self.assertRaises(vocab.VocabularyError)):
            vocab.download()

    def test_the_root_must_be_an_existing_absolute_directory_outside_the_checkout(self) -> None:
        for env in ({}, {"POLICYOPS_TEMP_DIR": "relative"}, {"POLICYOPS_TEMP_DIR": str(REPO)},
                    {"POLICYOPS_TEMP_DIR": str(REPO / "packages")},
                    {"POLICYOPS_TEMP_DIR": str(self.root / "missing")}):
            with self.subTest(env=env), self.assertRaises(vocab.VocabularyError):
                vocab.temp_root(env)
        self.assertEqual(vocab.destination(self.env), self.target)

    def test_a_linked_tokenizers_directory_into_the_checkout_is_refused_before_any_write(self) -> None:
        link_directory(self.root / "tokenizers", self.fake_checkout / "ingress")
        with mock.patch.object(vocab, "ROOT", self.fake_checkout):
            self.assertEqual(vocab.main(["--from-file", str(self.source())], self.env), 1)
        self.assertEqual(list((self.fake_checkout / "ingress").iterdir()), [])  # nothing written through the link

    def test_any_linked_tokenizers_directory_is_refused_even_outside_the_checkout(self) -> None:
        link_directory(self.root / "tokenizers", self.elsewhere)
        self.assertEqual(vocab.main(["--from-file", str(self.source())], self.env), 1)
        self.assertEqual(list(self.elsewhere.iterdir()), [])

    def test_a_link_at_the_destination_name_is_refused(self) -> None:
        (self.root / "tokenizers").mkdir()
        link_directory(self.target, self.elsewhere)
        self.assertEqual(vocab.main(["--from-file", str(self.source())], self.env), 1)
        self.assertEqual(list(self.elsewhere.iterdir()), [])

    def test_parallel_writers_use_their_own_partials_and_leave_one_verified_file(self) -> None:
        start = threading.Barrier(4)
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                start.wait(10)
                vocab.install(DATA, self.root)
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=writer) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual((errors, self.target.read_bytes(), self.partials()), ([], DATA, []))

    def test_an_open_reader_on_the_pinned_destination_is_accepted_not_a_failure(self) -> None:
        """Windows refuses to replace a file another handle has open; the same pinned bytes are then accepted."""
        vocab.install(DATA, self.root)
        with self.target.open("rb"):  # a concurrent writer's verification read
            self.assertEqual(vocab.install(DATA, self.root), self.target)
        self.assertEqual((self.target.read_bytes(), self.partials()), (DATA, []))

    def test_a_refused_replace_is_accepted_only_for_the_pinned_bytes(self) -> None:
        refused = mock.patch.object(vocab.os, "replace", side_effect=PermissionError(13, "in use"))
        vocab.install(DATA, self.root)
        with refused:
            self.assertEqual(vocab.install(DATA, self.root), self.target)  # accepted: already pinned
        self.target.write_bytes(b"other bytes")
        with refused, self.assertRaises(PermissionError):
            vocab.install(DATA, self.root)  # an unverified destination is never accepted
        self.assertEqual((self.target.read_bytes(), self.partials()), (b"other bytes", []))

    def test_concurrent_writers_of_the_real_vocabulary_all_succeed(self) -> None:
        provisioned = Path(os.environ["POLICYOPS_TEMP_DIR"]) / "tokenizers" / "cl100k_base.tiktoken"
        data = provisioned.read_bytes()  # the real 1.68 MB file; the tests never download it
        with mock.patch.object(vocab, "SHA256", hashlib.sha256(data).hexdigest()):
            self.assertEqual(vocab.SHA256, "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7")
            for _trial in range(3):
                start = threading.Barrier(4)
                errors: list[BaseException] = []

                def writer(start: threading.Barrier = start, errors: list[BaseException] = errors) -> None:
                    try:
                        start.wait(10)
                        vocab.install(data, self.root)
                    except BaseException as error:  # collected and asserted below
                        errors.append(error)

                threads = [threading.Thread(target=writer) for _ in range(4)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(60)
                self.assertEqual(([t.is_alive() for t in threads], errors), ([False] * 4, []))
                self.assertEqual((hashlib.sha256(self.target.read_bytes()).hexdigest(), self.partials()),
                                 (vocab.SHA256, []))

    def test_a_failed_write_removes_only_its_own_partial(self) -> None:
        (self.root / "tokenizers").mkdir()
        other = self.root / "tokenizers" / ".cl100k_base.tiktoken.another-writer.partial"
        other.write_bytes(b"another writer's work in progress")
        with (mock.patch.object(vocab.os, "replace", side_effect=OSError("replace failed")),
              self.assertRaises(OSError)):
            vocab.install(DATA, self.root)
        self.assertEqual(self.partials(), [other.name])  # ours is gone, theirs is untouched
        self.assertEqual(other.read_bytes(), b"another writer's work in progress")
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
