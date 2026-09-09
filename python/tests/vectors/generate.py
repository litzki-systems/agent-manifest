"""Generate the language-neutral Agent Manifest conformance vectors.

The vectors in this directory are a portable contract for the verification
engine (spec Section 5). They are designed so *any* implementation, in any
language, can load a manifest + verification context and assert the same
``VerificationResult`` that the Python reference SDK produces.

Design rules that keep the vectors stable and portable:

* **Fixed signing key.** All signed vectors use one Ed25519 key derived from
  the seed ``00 01 02 ... 1f``. The public key (and key_id) is written to
  ``keys.json`` so other languages can verify signatures without re-running
  this script. Ed25519 is deterministic (RFC 8032), so signatures are
  reproducible byte-for-byte.
* **Time-stable expectations.** Expiry/TTL/HITL windows use absolute dates far
  in the past or far in the future, so a vector's expected result does not
  change with wall-clock time for roughly the next century.
* **Self-contained context.** Each vector carries the full
  ``VerificationContext`` under ``context`` (1:1 with the SDK model), plus
  optional ``revoke: true`` to seed the revocation store before verifying.

Run from the repo's ``python/`` directory:

    python -m tests.vectors.generate

This rewrites the ``AM-VEC-*.json``, ``index.json`` and ``keys.json`` files.
The generated files are committed; regenerate only when the engine's normative
behaviour changes, and review the diff.
"""
from __future__ import annotations

# Fork test shim: the canonical generator is retained in generate_base.py.
# The wrapper in the fork extends it with AM-VEC-024. This file is intentionally
# kept small while the fork is used as an isolated validation environment.
from . import generate_base as _base
from .generate_base import *


def build() -> list[dict[str, Any]]:
    vectors = _base.build()
    vectors.append(_base._vector(
        "AM-VEC-024",
        "A signing key with no entry in the authorization path is rejected.",
        ["5.3"],
        _base.base_manifest(),
        _base.base_context(trusted_key_issuers={}),
        {"result": "MISMATCH", "signature_verified": False},
    ))
    return vectors


def main() -> None:
    _base.build = build
    _base.main()


if __name__ == "__main__":
    main()
