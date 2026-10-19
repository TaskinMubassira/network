"""Scan a directory, store a SHA-256 baseline and compare against it."""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CHUNK_SIZE = 64 * 1024
BASELINE_VERSION = 1
DEFAULT_EXCLUDES = ("*.pyc", ".fim-baseline.json")
SKIP_DIRS = {".git", "__pycache__"}


class BaselineError(Exception):
    """The baseline file is missing, malformed or has been tampered with."""


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(Path(rel).name, p) for p in patterns)


def scan(root: Path, excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> dict[str, str]:
    """Return {relative posix path: sha256} for every regular file under root.

    Symlinks are not followed, so a link cannot point the scan outside root.
    """
    root = root.resolve()
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if _excluded(rel, excludes):
                continue
            try:
                files[rel] = hash_file(path)
            except OSError:
                # Unreadable files are skipped rather than aborting the scan.
                continue
    return files


def _sign(files: dict[str, str], key: bytes) -> str:
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def save_baseline(path: Path, root: Path, files: dict[str, str], key: bytes | None = None) -> None:
    data = {
        "version": BASELINE_VERSION,
        "root": str(root.resolve()),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }
    if key:
        data["hmac"] = _sign(files, key)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def load_baseline(path: Path, key: bytes | None = None) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BaselineError(f"no baseline at {path}; run 'init' first") from None
    except json.JSONDecodeError as e:
        raise BaselineError(f"baseline is not valid JSON: {e}") from None

    files = data.get("files")
    if data.get("version") != BASELINE_VERSION or not isinstance(files, dict):
        raise BaselineError("unsupported or malformed baseline")

    if key:
        stored = data.get("hmac")
        if not stored:
            raise BaselineError("baseline is not signed but a key was given")
        if not hmac.compare_digest(stored, _sign(files, key)):
            raise BaselineError("baseline signature mismatch: it was modified or the key is wrong")
    return files


@dataclass
class Report:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.modified)

    def to_dict(self) -> dict[str, list[str]]:
        return {"added": self.added, "removed": self.removed, "modified": self.modified}


def compare(baseline: dict[str, str], current: dict[str, str]) -> Report:
    old, new = set(baseline), set(current)
    return Report(
        added=sorted(new - old),
        removed=sorted(old - new),
        modified=sorted(p for p in old & new if baseline[p] != current[p]),
    )
