"""Streaming file digests and explicit rotating application logging."""

import hashlib
import logging
import os
import stat
from logging.handlers import RotatingFileHandler
from pathlib import Path

from models import ProviderResult, Verdict  # Compatibility imports for integrations.

__all__ = ["ProviderResult", "Verdict", "calculate_file_hashes", "setup_logging"]


def setup_logging(directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    logger = logging.getLogger("threatlens")
    target = str((directory / "threatlens.log").resolve())
    for existing in list(logger.handlers):
        if getattr(existing, "baseFilename", None) != target:
            existing.close()
            logger.removeHandler(existing)
    if not logger.handlers:
        handler = RotatingFileHandler(
            directory / "threatlens.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        (directory / "threatlens.log").chmod(0o600)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def calculate_file_hashes(path: str) -> dict:
    """Single pass, 64-KiB chunks; MD5/SHA1 identify samples, SHA256 is queried.

    Non-regular files are rejected. Metadata changes during reading invalidate the
    result; for forensic consistency scan a stable copy/snapshot of the sample.
    """
    target = Path(path).expanduser()
    if not target.is_file():
        raise ValueError("Expected a readable regular file")
    digests = {x: hashlib.new(x, usedforsecurity=False) for x in ("md5", "sha1", "sha256")}
    with target.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Expected a regular file")
        size = 0
        for chunk in iter(lambda: handle.read(65536), b""):
            size += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
        after = os.fstat(handle.fileno())
    if (before.st_size, before.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    ) or size != after.st_size:
        raise ValueError("File changed while hashing; scan a stable copy")
    return {"filename": target.name, "size": size, **{k: v.hexdigest() for k, v in digests.items()}}
