"""Decrypt a session/backup bundle exported by the Pendora app and emit it in
the key-file format this SDK understands (``ypsopump_keys.json``).

The app seals exports with Argon2id (key derivation) + XChaCha20-Poly1305
(AEAD). The decrypted payload is a "vault": phone identity, server key, and a
map of pump sessions. ``to_sdk_keys`` converts one session into the flat
key-file shape the SDK reads, ready to drop in as ``ypsopump_keys.json``.
"""

import json
import uuid
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt


class BundleError(Exception):
    pass


# --- bundle decryption -----------------------------------------------------

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
    """Decrypt a parsed bundle dict and return the JSON payload (the vault)."""
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
    return open_bundle(json.loads(Path(path).read_text()), password)


# --- serial -> address helpers (same rules as pairing.py) ------------------

def serial_to_mac(serial: str) -> str:
    num = int(serial)
    num = num - 10000000 if num > 10000000 else num
    hex_str = f"{num:06X}"
    mac = "EC:2A:F0"
    for i, c in enumerate(hex_str):
        mac += ":" if i % 2 == 0 and i > 0 else ""
        mac += c
    return mac


def serial_to_bt_address(serial: str) -> bytes:
    num = int(serial) % 10000000
    little = num.to_bytes(4, "little")
    suffix = bytes([little[2], little[1], little[0]])
    return bytes([0xEC, 0x2A, 0xF0]) + suffix


# --- vault payload -> SDK key file -----------------------------------------

def to_sdk_keys(payload: dict, serial: str | None = None, device_id: str | None = None) -> dict:
    """Convert one session of a decrypted vault into ypsopump_keys.json shape."""
    vault = payload.get("vault") or {}
    sessions = vault.get("sessions") or {}
    if not sessions:
        raise BundleError("no sessions in bundle")
    if serial is None:
        if len(sessions) == 1:
            serial = next(iter(sessions))
        else:
            raise BundleError(
                "bundle has several sessions; pass --serial (one of: "
                + ", ".join(sorted(sessions)) + ")"
            )
    if serial not in sessions:
        raise BundleError(
            f"no session for {serial} (have: {', '.join(sorted(sessions))})"
        )
    sess = sessions[serial]
    server_key = sess.get("serverKey") or vault.get("serverKey") or {}
    if "privateKeyHex" not in server_key:
        raise BundleError("session has no server key")
    phone = vault.get("phone") or {}
    counters = sess.get("counters") or {}
    return {
        "private_key": phone.get("privateKeyHex"),
        "device_id": device_id or str(uuid.uuid4()),
        "server_key": {
            "slot": server_key.get("slot", 0),
            "privateKeyHex": server_key["privateKeyHex"],
        },
        "pump": {
            "serial": serial,
            "mac": serial_to_mac(serial),
            "bt_address": serial_to_bt_address(serial).hex(),
            "ble_address": None,
            "shared_key": sess["sharedKeyHex"],
            "shared_key_expires_at": sess.get("expiresAt"),
            "pump_public_key": sess.get("pumpPublicKeyHex"),
            "challenge": None,
            "server_nonce": None,
            "read_counter": counters.get("readCounter", 0),
            "write_counter": counters.get("writeCounter", 0),
            "reboot_counter": counters.get("rebootCounter", 0),
        },
    }


def _main(argv=None) -> int:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(
        description="Decrypt a Pendora export and print it as ypsopump_keys.json."
    )
    ap.add_argument("file", help="path to the exported .json bundle")
    ap.add_argument("-p", "--password", help="export password (prompted if omitted)")
    ap.add_argument("--serial", help="which pump session to emit (required if several)")
    ap.add_argument("-o", "--out", help="write to this file instead of stdout")
    args = ap.parse_args(argv)

    password = args.password or getpass.getpass("Export password: ")
    payload = open_bundle_file(args.file, password)
    keys = to_sdk_keys(payload, serial=args.serial)
    text = json.dumps(keys, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
