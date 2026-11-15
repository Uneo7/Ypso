"""Decrypt a session/backup bundle exported by the Pendora app.

The app seals exports with Argon2id (key derivation) + XChaCha20-Poly1305
(AEAD). The bundle is JSON:

    {
      "version": 1,
      "kdf": {"name": "argon2id", "t": <iters>, "m": <KiB>, "p": <lanes>},
      "saltHex":  "...",   # 16 bytes
      "nonceHex": "...",   # 24 bytes
      "ciphertextHex": "..."
    }

The decrypted payload is the backup object: {backupVersion, exportedAt,
vault, counters}. `vault.sessions[serial]` holds each pump session
(serverKey, pumpPublicKeyHex, sharedKeyHex, counters, ...).
"""

import json
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt


class BundleError(Exception):
    pass


def _derive_key(password: str, salt: bytes, kdf: dict) -> bytes:
    if kdf.get("name") != "argon2id":
        raise BundleError(f"unsupported kdf {kdf.get('name')!r}")
    # noble's `m` is memory in KiB, matching argon2-cffi's memory_cost.
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=int(kdf["t"]),
        memory_cost=int(kdf["m"]),
        parallelism=int(kdf["p"]),
        hash_len=32,
        type=Type.ID,
    )


def open_bundle(bundle: dict, password: str) -> dict:
    """Decrypt a parsed bundle dict and return the JSON payload."""
    for field in ("kdf", "saltHex", "nonceHex", "ciphertextHex"):
        if field not in bundle:
            raise BundleError(f"bundle missing {field!r}")
    key = _derive_key(password, bytes.fromhex(bundle["saltHex"]), bundle["kdf"])
    nonce = bytes.fromhex(bundle["nonceHex"])
    ciphertext = bytes.fromhex(bundle["ciphertextHex"])
    try:
        plain = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", nonce, key)
    except Exception as e:  # noqa: BLE001 - map to a clear error
        raise BundleError("wrong password, or the bundle has been altered") from e
    return json.loads(plain.decode("utf-8"))


def open_bundle_file(path, password: str) -> dict:
    """Read a bundle JSON file and decrypt it."""
    return open_bundle(json.loads(Path(path).read_text()), password)


def sessions_from(payload: dict) -> dict:
    """Pull the {serial: session} map out of a decrypted payload."""
    return (payload.get("vault") or {}).get("sessions") or {}


def _main(argv=None) -> int:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(description="Decrypt a Pendora session/backup export.")
    ap.add_argument("file", help="path to the exported .json bundle")
    ap.add_argument("-p", "--password", help="export password (prompted if omitted)")
    ap.add_argument("--sessions-only", action="store_true", help="print only the sessions map")
    args = ap.parse_args(argv)

    password = args.password or getpass.getpass("Export password: ")
    payload = open_bundle_file(args.file, password)
    out = sessions_from(payload) if args.sessions_only else payload
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
