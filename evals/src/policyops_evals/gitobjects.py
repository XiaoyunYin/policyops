"""Verify Git objects by their content hashes, independently of the git binary.

Git is used only to transport and store objects. Every commit, tree and blob read
back is re-hashed here (`sha1("<type> <size>\\0" + body)`), so a corrupted object
store or a substituted object cannot pass as the pinned commit. SHA-1 alone has
known collision weaknesses, which is why the reviewed manifests also pin SHA-256
for every file PolicyOps consumes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
import hashlib
import re
from typing import Any


HEX40 = re.compile(r"[0-9a-f]{40}")
REGULAR_MODES = {"100644", "100755"}
TREE_MODE = "40000"
SYMLINK_MODE = "120000"
GITLINK_MODE = "160000"
KNOWN_MODES = REGULAR_MODES | {TREE_MODE, SYMLINK_MODE, GITLINK_MODE}
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}


class ObjectError(ValueError):
    """An object is missing, malformed or does not hash to its name."""


def object_id(kind: str, body: bytes) -> str:
    return hashlib.sha1(f"{kind} {len(body)}\0".encode("ascii") + body, usedforsecurity=False).hexdigest()


def check_object(oid: str, kind: str, body: bytes, expected_kind: str) -> None:
    if kind != expected_kind:
        raise ObjectError(f"{oid}: expected {expected_kind}, got {kind}")
    if object_id(kind, body) != oid:
        raise ObjectError(f"{oid}: {kind} content does not hash to its object ID")


def commit_tree(body: bytes) -> str:
    first = body.split(b"\n", 1)[0].decode("ascii", errors="replace")
    kind, _, oid = first.partition(" ")
    if kind != "tree" or not HEX40.fullmatch(oid):
        raise ObjectError("commit object does not start with a tree line")
    return oid


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    name: str
    oid: str


def parse_tree(body: bytes) -> list[TreeEntry]:
    entries = []
    position = 0
    while position < len(body):
        space = body.index(b" ", position)
        nul = body.index(b"\0", space)
        mode = body[position:space].decode("ascii")
        name = body[space + 1:nul].decode("utf-8")
        raw = body[nul + 1:nul + 21]
        if len(raw) != 20:
            raise ObjectError("truncated tree entry")
        if mode not in KNOWN_MODES:
            raise ObjectError(f"unknown tree entry mode {mode}")
        entries.append(TreeEntry(mode, name, raw.hex()))
        position = nul + 21
    return entries


def check_component(name: str) -> None:
    """Reject names that could escape or alias a materialized path on Windows/POSIX."""
    stem = name.split(".", 1)[0].casefold()
    if (
        not name or name in {".", ".."} or any(char in name for char in '/\\:*?"<>|\0')
        or any(ord(char) < 32 for char in name) or name.endswith((".", " ")) or stem in WINDOWS_RESERVED
        or name.casefold() == ".git"
    ):
        raise ObjectError(f"unsafe path component {name!r}")


@dataclass(frozen=True)
class FileEntry:
    path: str
    mode: str
    oid: str


ReadObject = Callable[[str], tuple[str, bytes]]


def build_tree_id(entries: Iterable[tuple[str, str, str]]) -> str:
    """Root tree ID for (path, mode, blob ID) entries, rebuilt the way Git writes tree objects.

    Entries sort by name bytes, with a subtree compared as if its name ended in
    "/". Rebuilding from blob IDs computed over actual file bytes ties every file
    to the pinned root tree without trusting any recorded hash.
    """
    root: dict[str, Any] = {}
    for path, mode, oid in entries:
        *directories, name = path.split("/")
        node = root
        for directory in directories:
            node = node.setdefault(directory, {})
            if not isinstance(node, dict):
                raise ObjectError(f"{path}: a file and a directory share a path")
        if name in node:
            raise ObjectError(f"{path}: duplicate tree entry")
        node[name] = (mode, oid)

    def write(node: dict[str, Any]) -> str:
        items = []
        for name, value in node.items():
            if isinstance(value, dict):
                items.append((name.encode() + b"/", TREE_MODE, name, write(value)))
            else:
                items.append((name.encode(), value[0], name, value[1]))
        body = b"".join(f"{mode} {name}".encode() + b"\0" + bytes.fromhex(oid)
                        for _, mode, name, oid in sorted(items, key=lambda item: item[0]))
        return object_id("tree", body)

    return write(root)


def walk_tree(read: ReadObject, tree_oid: str, prefix: str = "") -> Iterator[FileEntry]:
    """Yield every non-tree entry below tree_oid, verifying each tree object on the way."""
    kind, body = read(tree_oid)
    check_object(tree_oid, kind, body, "tree")
    for entry in parse_tree(body):
        check_component(entry.name)
        path = f"{prefix}{entry.name}"
        if entry.mode == TREE_MODE:
            yield from walk_tree(read, entry.oid, path + "/")
        else:
            yield FileEntry(path, entry.mode, entry.oid)
