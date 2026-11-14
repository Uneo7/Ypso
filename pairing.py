import asyncio
import hashlib
import json
import uuid
import sys
import subprocess
import time
import grpc
from pathlib import Path
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError
from nacl.public import PrivateKey
from nacl.encoding import HexEncoder
from nacl.bindings import crypto_scalarmult
from proto import encrypt_key_pb2, encrypt_key_pb2_grpc

try:
    pass
except ImportError:
    print("⚠️  gRPC stubs not found. Run: python compile_proto.py")
    print("Then run this script again.")
    import sys
    sys.exit(1)

from device_profiles import DEVICE_PROFILES, APP_INFO, CURRENT_DEVICE
from pump.constants import CHAR_AUTH_PASSWORD, CHAR_MASTER_VERSION, CHAR_BASE_VERSION, CHAR_SETTINGS_VERSION, CHAR_HISTORY_VERSION
from pump.utils import compute_password
from pump.server_blob import build_challenge_response

SALT = bytes([0x4F, 0xC2, 0x45, 0x4D, 0x9B, 0x81, 0x59, 0xA4, 0x93, 0xBB])
KEY_FILE = Path("ypsopump_keys.json")
SERVER_BLOB_TTL = 28 * 24 * 3600


def load_server_key():
    if not KEY_FILE.exists():
        return None
    sk = (json.loads(KEY_FILE.read_text()).get("server_key") or {})
    hexkey = sk.get("private_key") or sk.get("privateKeyHex")
    if not hexkey or "<" in hexkey:
        return None
    return sk.get("slot", 0), bytes.fromhex(hexkey)

SERVICE_CRYPTO = "fb349b5f-8000-0080-0010-0000feda0002"
CHAR_REQUEST_PUBLIC_KEY = "669a0c20-0008-969e-e211-fcff0000000a"
CHAR_WRITE_CHALLENGE = "669a0c20-0008-969e-e211-fcff0000000b"
CHAR_EXTENDED_READ = "669a0c20-0008-969e-e211-fcff000000ff"

def _rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def hchacha20(key: bytes, nonce: bytes, const: bytes = b"expand 32-byte k") -> bytes:
    import struct

    if len(key) != 32 or len(nonce) != 16:
        raise ValueError("Invalid HChaCha20 key/nonce size")
    if len(const) != 16:
        raise ValueError("Invalid constant size")

    state = list(struct.unpack('<4I', const) + struct.unpack('<8I', key) + struct.unpack('<4I', nonce))
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    output_words = state[:4] + state[12:]
    return struct.pack('<8I', *output_words)

def serial_to_mac(serial):
    num = int(serial)
    num = num - 10000000 if num > 10000000 else num
    hex_str = f"{num:06X}"
    mac = "EC:2A:F0"
    for i, c in enumerate(hex_str):
        mac += ":" if i % 2 == 0 and i > 0 else ""
        mac += c
    return mac


def serial_to_bt_address(serial):
    num = int(serial) % 10000000
    little = num.to_bytes(4, "little")
    suffix = bytes([little[2], little[1], little[0]])
    return bytes([0xEC, 0x2A, 0xF0]) + suffix


async def discover_pump(timeout=10.0):
    print("Scanning for pump...")
    devices = await BleakScanner.discover(timeout=timeout)
    pump = next((d for d in devices if d.name and "YpsoPump" in d.name), None)
    if not pump:
        return None
    print(f"Found: {pump.name} ({pump.address})")
    serial = pump.name.split("_")[1]
    mac = serial_to_mac(serial)
    bt_address_bytes = serial_to_bt_address(serial)
    update_pump_cache(
        serial=serial,
        mac=mac,
        bt_address=bt_address_bytes.hex(),
        ble_address=pump.address
    )
    return pump.address, serial, mac, bt_address_bytes


def print_summary(bt_address_bytes, device_id, app_public_key_hex, challenge_hex,
                  pump_public_key_hex, server_nonce_hex, shared_key_hex,
                  header="KEY EXCHANGE COMPLETE"):
    print("\n" + "=" * 60)
    print(header)
    print("=" * 60)
    print(f"BT Address      : {bt_address_bytes.hex()}")
    print(f"Device ID       : {device_id}")
    print(f"App Public Key  : {app_public_key_hex}")
    print(f"Challenge       : {challenge_hex}")
    print(f"Pump Public Key : {pump_public_key_hex}")
    if server_nonce_hex:
        print(f"Server Nonce    : {server_nonce_hex}")
    print(f"Shared Key      : {shared_key_hex}")
    print("=" * 60)

def load_or_generate_keys():
    if KEY_FILE.exists():
        with open(KEY_FILE) as f:
            data = json.load(f)
        private_key = PrivateKey(bytes.fromhex(data["private_key"]))
        device_id = data["device_id"]
        pump_info = data.get("pump")
        print(f"Loaded existing keys (device_id: {device_id})")
        return private_key, device_id, pump_info

    private_key = PrivateKey.generate()
    device_id = str(uuid.uuid4())
    data = {
        "private_key": private_key.encode(encoder=HexEncoder).decode(),
        "device_id": device_id,
        "pump": None
    }
    with open(KEY_FILE, "w") as f:
        json.dump(data, f)

    print(f"Generated new keys (device_id: {device_id})")
    return private_key, device_id, None


def update_pump_cache(**updates):
    if not KEY_FILE.exists():
        return
    with open(KEY_FILE) as f:
        data = json.load(f)
    pump = data.get("pump") or {}
    for key, value in updates.items():
        pump[key] = value
    data["pump"] = pump
    with open(KEY_FILE, "w") as f:
        json.dump(data, f)


def load_cached_session(pump_info):
    if not pump_info:
        return None
    shared_key_hex = pump_info.get("shared_key")
    expires_at = pump_info.get("shared_key_expires_at")
    if not (shared_key_hex and expires_at):
        return None
    if time.time() > expires_at:
        return None
    return {
        "shared_key": bytes.fromhex(shared_key_hex),
        "challenge": pump_info.get("challenge"),
        "pump_public_key": pump_info.get("pump_public_key"),
        "server_nonce": pump_info.get("server_nonce"),
        "read_counter": pump_info.get("read_counter", 0),
        "write_counter": pump_info.get("write_counter", 0),
        "reboot_counter": pump_info.get("reboot_counter", 0),
        "expires_at": expires_at,
    }


def cache_session(challenge, pump_public_key, server_nonce, shared_key):
    update_pump_cache(
        challenge=challenge.hex(),
        pump_public_key=pump_public_key.hex(),
        server_nonce=server_nonce.hex(),
        shared_key=shared_key.hex(),
        shared_key_expires_at=time.time() + 28 * 24 * 3600,
        read_counter=0,
        write_counter=0,
        reboot_counter=0,
    )

def get_play_integrity_token(nonce_hex):
    script = Path(__file__).parent / "play_integrity.py"
    result = subprocess.run([sys.executable, str(script), nonce_hex], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"play_integrity.py failed: {result.stderr.strip()}")
    token = result.stdout.strip()
    if not token:
        raise RuntimeError("play_integrity.py returned no token")
    return token

def _hex(data: bytes) -> str:
    return data.hex().upper()


def encrypt_key_request(bt_address, server_nonce, challenge, pump_pubkey, app_pubkey, token):
    device = DEVICE_PROFILES[CURRENT_DEVICE]
    metrics = encrypt_key_pb2.Metrics(
        platform=device["platform"],
        model=device["model"],
        os_type=device["os_type"],
        os_version=device["os_version"],
        manufacturer=device["manufacturer"],
        device_serial="na",
        application_name=APP_INFO["application_name"],
        application_package=APP_INFO["application_package"],
        library_version=APP_INFO["library_version"],
        xamarin=APP_INFO["xamarin"]
    )
    request = encrypt_key_pb2.EncryptKeyRequest(
        challenge=_hex(challenge),
        pump_public_key=_hex(pump_pubkey),
        app_public_key=_hex(app_pubkey),
        bt_address=_hex(bt_address),
        message_attestation_object=token,
        nonce=_hex(server_nonce),
        metrics=metrics
    )
    channel = grpc.secure_channel(
        'connect.ml.pr.sec01.proregia.io:8090',
        grpc.ssl_channel_credentials()
    )
    try:
        stub = encrypt_key_pb2_grpc.EncryptKeyStub(channel)
        response = stub.Send(request)
        return bytes.fromhex(response.encrypted_bytes)
    finally:
        channel.close()

def compute_shared_key(app_privkey, pump_pubkey):
    secret = crypto_scalarmult(bytes(app_privkey), pump_pubkey)
    return hchacha20(secret, b"\x00" * 16)

def get_server_nonce(bt_address, device_id):
    """
    Call Ypsomed server to get ServerNonce.
    Spoofs Android device metrics to match official app.
    """
    channel = grpc.secure_channel(
        'connect.ml.pr.sec01.proregia.io:8090',
        grpc.ssl_channel_credentials()
    )

    stub = encrypt_key_pb2_grpc.NonceRequestStub(channel)

    # Get device profile
    device = DEVICE_PROFILES[CURRENT_DEVICE]

    # Build metrics matching official app
    metrics = encrypt_key_pb2.Metrics(
        platform=device["platform"],
        model=device["model"],
        os_type=device["os_type"],
        os_version=device["os_version"],
        manufacturer=device["manufacturer"],
        device_serial="na",
        application_name=APP_INFO["application_name"],
        application_package=APP_INFO["application_package"],
        library_version=APP_INFO["library_version"],
        xamarin=APP_INFO["xamarin"]
    )

    request = encrypt_key_pb2.DeviceIdentifier(
        device_id=device_id,
        bt_address=bt_address.hex(),
        metrics=metrics
    )

    print(f"Spoofing as: {device['manufacturer']} {device['model']} (Android {device['os_version']})")

    response = stub.Send(request)
    channel.close()

    return bytes.fromhex(response.server_nonce)

async def read_extended_char(client, first_char_uuid, extended_read_uuid):
    frames = []
    
    first_frame = await client.read_gatt_char(first_char_uuid)
    header = first_frame[0]
    total_frames = header & 0x0F or 1
    frames.append(first_frame)
    
    for _ in range(total_frames - 1):
        frame = await client.read_gatt_char(extended_read_uuid)
        frames.append(frame)
    
    merged = bytearray()
    for frame in frames:
        merged.extend(frame[1:])
    
    return bytes(merged)

async def write_extended_char(client, char_uuid, data):
    chunk_size = 19
    total_frames = (len(data) + chunk_size - 1) // chunk_size
    for i in range(total_frames):
        start = i * chunk_size
        end = min(start + chunk_size, len(data))
        chunk = data[start:end]
        header = ((i + 1) << 4) | total_frames
        frame = bytes([header]) + chunk
        await client.write_gatt_char(char_uuid, frame)
        await asyncio.sleep(0.05)

async def main():
    private_key, device_id, pump_info = load_or_generate_keys()
    public_key = private_key.public_key

    pump_info = pump_info or {}
    serial = pump_info.get("serial")
    mac = pump_info.get("mac")
    ble_address = pump_info.get("ble_address")
    bt_address_hex = pump_info.get("bt_address")
    bt_address_bytes = bytes.fromhex(bt_address_hex) if bt_address_hex else None

    if serial:
        expected_mac = serial_to_mac(serial)
        expected_bt_hex = serial_to_bt_address(serial).hex()
        if mac != expected_mac or bt_address_hex != expected_bt_hex:
            mac = expected_mac
            bt_address_hex = expected_bt_hex
            bt_address_bytes = bytes.fromhex(bt_address_hex)
            update_pump_cache(mac=mac, bt_address=bt_address_hex)

    if not (serial and mac and bt_address_bytes and ble_address):
        discovery = await discover_pump()
        if not discovery:
            print("No pump found")
            return
        ble_address, serial, mac, bt_address_bytes = discovery
        with open(KEY_FILE) as f:
            pump_info = json.load(f).get("pump", {})
    else:
        print(f"Using cached pump: {serial} ({ble_address})")

    cached_session = load_cached_session(pump_info)
    if cached_session and bt_address_bytes:
        expires_in = int(cached_session["expires_at"] - time.time())
        print(f"Cached shared key valid for {max(expires_in,0)//3600}h ─ skipping key exchange")
        print_summary(
            bt_address_bytes,
            device_id,
            public_key.encode(encoder=HexEncoder).decode(),
            cached_session.get("challenge", "n/a"),
            cached_session.get("pump_public_key", "n/a"),
            cached_session.get("server_nonce", "n/a"),
            cached_session["shared_key"].hex(),
            header="CACHED KEY EXCHANGE"
        )
        return

    async def run_session(current_ble_address, serial, mac, bt_address_bytes):
        password = compute_password(mac)
        print(f"Serial: {serial}")
        print(f"MAC: {mac}")
        print(f"BT Address: {bt_address_bytes.hex()}")
        print(f"\nApp Public Key: {public_key.encode(encoder=HexEncoder).decode()}")

        server_key = load_server_key()
        offline = server_key is not None
        server_nonce = b""
        if offline:
            print(f"\n=== Offline pairing (server key slot {server_key[0]}) ===")
        else:
            print("\n=== Calling Ypsomed Server ===")
            try:
                server_nonce = get_server_nonce(bt_address_bytes, device_id)
                print(f"Server Nonce (24 bytes): {server_nonce.hex()}")
            except Exception as e:
                print(f"Server call failed: {e}")
                return False

        async with BleakClient(current_ble_address) as client:
            print(f"Connected ({current_ble_address}): {client.is_connected}")

            try:
                await client.pair()
            except Exception:
                pass

            await asyncio.sleep(1)

            print("\n=== Authenticating ===")
            await client.write_gatt_char(CHAR_AUTH_PASSWORD, password)

            await asyncio.sleep(0.5)

            print("\n=== Reading Versions ===")
            master_ver = await client.read_gatt_char(CHAR_MASTER_VERSION)
            print(f"Master: {master_ver.decode('utf-8').rstrip(chr(0))}")

            base_ver = await client.read_gatt_char(CHAR_BASE_VERSION)
            print(f"Base: {base_ver.decode('utf-8').rstrip(chr(0))}")

            settings_ver = await client.read_gatt_char(CHAR_SETTINGS_VERSION)
            print(f"Settings: {settings_ver.decode('utf-8').rstrip(chr(0))}")

            history_ver = await client.read_gatt_char(CHAR_HISTORY_VERSION)
            print(f"History: {history_ver.decode('utf-8').rstrip(chr(0))}")

            print("\n=== Reading Pump Public Key & Challenge ===")
            pub_key_data = await read_extended_char(client, CHAR_REQUEST_PUBLIC_KEY, CHAR_EXTENDED_READ)

            if len(pub_key_data) < 64:
                print(f"Error: unexpected length for pub_key_data ({len(pub_key_data)}), aborting.")
                return False
            challenge = pub_key_data[0:32]
            pump_public_key = pub_key_data[32:64]

            print(f"\nChallenge (32 bytes):\n{challenge.hex()}")
            print(f"\nPump Public Key (32 bytes):\n{pump_public_key.hex()}")

            if offline:
                print("\n=== Building Challenge Response (offline) ===")
                encrypted_bytes = build_challenge_response(
                    server_key[1], pump_public_key, challenge, bytes(public_key), SERVER_BLOB_TTL
                )
            else:
                print("\n=== Getting Play Integrity Token ===")
                try:
                    token = get_play_integrity_token(server_nonce.hex())
                    print(f"Token (truncated): {token[:80]}...")
                except Exception as e:
                    print(f"Failed to obtain Play Integrity token: {e}")
                    return False

                print("\n=== Calling EncryptKey ===")
                try:
                    encrypted_bytes = encrypt_key_request(
                        bt_address_bytes, server_nonce, challenge, pump_public_key,
                        bytes(public_key), token
                    )
                except Exception as e:
                    print(f"EncryptKey call failed: {e}")
                    return False
            print(f"Encrypted Payload ({len(encrypted_bytes)} bytes): {encrypted_bytes.hex()}")

            print("\n=== Writing Challenge Response ===")
            await write_extended_char(client, CHAR_WRITE_CHALLENGE, encrypted_bytes)
            print("Challenge written successfully")

            shared_key = compute_shared_key(private_key, pump_public_key)
            cache_session(challenge, pump_public_key, server_nonce, shared_key)
            print_summary(
                bt_address_bytes,
                device_id,
                public_key.encode(encoder=HexEncoder).decode(),
                challenge.hex(),
                pump_public_key.hex(),
                server_nonce.hex(),
                shared_key.hex(),
            )
            return True

    while True:
        try:
            ok = await run_session(ble_address, serial, mac, bt_address_bytes)
            if ok:
                break
            return
        except BleakError as e:
            print(f"BLE connection failed: {e}")
            update_pump_cache(ble_address=None)
            discovery = await discover_pump()
            if not discovery:
                print("No pump found on retry")
                return
            ble_address, serial, mac, bt_address_bytes = discovery

asyncio.run(main())
def load_cached_session(pump_info):
    if not pump_info:
        return None
    shared_key = pump_info.get("shared_key")
    expires_at = pump_info.get("shared_key_expires_at")
    if not (shared_key and expires_at):
        return None
    if time.time() > expires_at:
        return None
    return {
        "shared_key": bytes.fromhex(shared_key),
        "challenge": pump_info.get("challenge"),
        "pump_public_key": pump_info.get("pump_public_key"),
        "server_nonce": pump_info.get("server_nonce"),
        "read_counter": pump_info.get("read_counter", 0),
        "write_counter": pump_info.get("write_counter", 0),
        "reboot_counter": pump_info.get("reboot_counter", 0),
        "expires_at": expires_at,
    }


def cache_session(challenge, pump_public_key, server_nonce, shared_key):
    update_pump_cache(
        challenge=challenge.hex(),
        pump_public_key=pump_public_key.hex(),
        server_nonce=server_nonce.hex(),
        shared_key=shared_key.hex(),
        shared_key_expires_at=time.time() + 28 * 24 * 3600,
        read_counter=0,
        write_counter=0,
        reboot_counter=0,
    )
