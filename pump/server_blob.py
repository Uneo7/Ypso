import os
import struct

from nacl.bindings import (
    crypto_scalarmult,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)

SIGMA = b"expand 32-byte k"
ZERO16 = b"\x00" * 16


def _rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 16:
        raise ValueError("hchacha20 needs 32-byte key and 16-byte nonce")
    state = list(struct.unpack("<4I", SIGMA) + struct.unpack("<8I", key) + struct.unpack("<4I", nonce))
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<8I", *(state[:4] + state[12:]))


def server_shared_key(server_priv: bytes, pump_pub: bytes) -> bytes:
    if len(server_priv) != 32 or len(pump_pub) != 32:
        raise ValueError("server_priv and pump_pub must be 32 bytes")
    return hchacha20(crypto_scalarmult(server_priv, pump_pub), ZERO16)


def build_challenge_response(
    server_priv: bytes,
    pump_pub: bytes,
    challenge: bytes,
    app_pub: bytes,
    ttl: int,
    counter: int = 1,
) -> bytes:
    if len(challenge) != 32 or len(app_pub) != 32:
        raise ValueError("challenge and app_pub must be 32 bytes")
    key = server_shared_key(server_priv, pump_pub)
    nonce = os.urandom(24)
    plaintext = challenge + ttl.to_bytes(4, "little") + app_pub + counter.to_bytes(8, "little")
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, b"", nonce, key) + nonce


def decrypt_challenge_response(server_priv: bytes, pump_pub: bytes, blob: bytes) -> dict:
    key = server_shared_key(server_priv, pump_pub)
    nonce = blob[-24:]
    ciphertext = blob[:-24]
    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", nonce, key)
    return {
        "challenge": plaintext[0:32],
        "ttl": int.from_bytes(plaintext[32:36], "little"),
        "app_public_key": plaintext[36:68],
        "counter": int.from_bytes(plaintext[68:76], "little"),
        "plaintext": plaintext,
    }
