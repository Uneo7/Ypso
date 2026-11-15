import hashlib

from bleak import BleakClient

from .constants import AUTH_SALTS, CHAR_AUTH_PASSWORD, CHAR_EXTENDED_READ


def compute_password(mac: str, level=2) -> bytes:
    """MD5 password for CHAR_AUTH_PASSWORD.

    `level` is the access level the firmware implements: 1, 2 or 3 (see
    AUTH_SALTS in constants). 2 is ordinary application access and stays the
    default; 3 is needed for the test service's memory characteristics and
    for clearing the history. The names "app" (= 2) and "test" (= 3) are
    still accepted.
    """
    try:
        salt = AUTH_SALTS[level]
    except KeyError:
        raise ValueError(
            f"unknown auth level {level!r}, expected one of "
            f"{sorted(AUTH_SALTS, key=repr)}"
        ) from None
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    return hashlib.md5(mac_bytes + salt).digest()


def chunk_payload(data: bytes):
    if not data:
        return [b"\x10"]
    total = max(1, (len(data) + 18) // 19)
    frames = []
    for idx in range(total):
        chunk = data[idx * 19 : idx * 19 + 19]
        header = ((idx + 1) << 4 & 0xF0) | (total & 0x0F)
        frames.append(bytes([header]) + chunk)
    return frames


async def read_extended_char(client: BleakClient, first_uuid: str, ext_uuid: str = CHAR_EXTENDED_READ):
    first = await client.read_gatt_char(first_uuid)
    if not first:
        return b""
    header = first[0]
    total_frames = header & 0x0F or 1
    frames = [first]
    for _ in range(total_frames - 1):
        frames.append(await client.read_gatt_char(ext_uuid))
    merged = bytearray()
    for frame in frames:
        merged.extend(frame[1:])
    return bytes(merged)


def maybe_decrypt(label: str, data: bytes, validator, cryptor, warnings: list):
    if validator(data):
        return data
    if not cryptor:
        return data
    try:
        plain = cryptor.decrypt(data)
        if validator(plain):
            return plain
        warnings.append(f"{label}: decrypted payload failed validation")
    except Exception as exc:
        warnings.append(f"{label}: decrypt error {exc}")
    return data

