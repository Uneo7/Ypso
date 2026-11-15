import asyncio
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from bleak import BleakClient

from .cache import PumpCacheError, load_cache, reset_cached_counters, set_cached_write_counter
from .constants import (
    CHAR_AUTH_PASSWORD,
    CHAR_BASE_VERSION,
    CHAR_BOLUS_NOTIFICATION,
    CHAR_BOLUS_START_STOP,
    CHAR_BOLUS_STATUS,
    CHAR_HISTORY_VERSION,
    CHAR_MASTER_VERSION,
    CHAR_SETTINGS_VERSION,
    CHAR_SYSTEM_DATE,
    CHAR_SYSTEM_STATUS,
    CHAR_SYSTEM_TIME,
    CHAR_TBR_START_STOP,
    ENTRY_CONFIG,
)
from .crc import crc16, crc16_valid
from .crypto import PumpCryptor
from .entries import get_char_value, parse_entry, type_name
from .glb import create_glb_safe_var, decode_glb_safe_var, is_glb_safe_var
from .utils import chunk_payload, compute_password, maybe_decrypt, read_extended_char


def load_session(
    *,
    allow_expired: bool = False,
    allow_plain: bool = False,
    reset_counters: bool = False,
    set_write_counter: Optional[int] = None,
) -> Tuple[dict, dict, Optional[PumpCryptor]]:
    data, pump = load_cache(allow_expired=allow_expired)
    if reset_counters:
        reset_cached_counters(data)
        pump = data.get("pump") or pump
    if set_write_counter is not None:
        set_cached_write_counter(data, set_write_counter)
        pump = data.get("pump") or pump
    cryptor = None
    if not allow_plain:
        shared_key_hex = pump.get("shared_key")
        if not shared_key_hex:
            raise PumpCacheError("Pas de clé partagée. Utilisez --no-crypto ou refaites le pairing.")
        cryptor = PumpCryptor(bytes.fromhex(shared_key_hex), data)
    return data, pump, cryptor


@asynccontextmanager
async def authenticated_client(pump: dict):
    password = compute_password(pump["mac"])
    async with BleakClient(pump["ble_address"]) as client:
        try:
            await client.pair()
        except Exception:
            pass
        await asyncio.sleep(1)
        await client.write_gatt_char(CHAR_AUTH_PASSWORD, password, response=True)
        await asyncio.sleep(0.2)
        yield client


def _scale_insulin(units: float) -> int:
    from decimal import Decimal, ROUND_HALF_UP

    value = Decimal(str(units))
    if value < 0:
        raise ValueError("Insulin amount must be positive")
    scaled = (value * 100).to_integral_value(rounding=ROUND_HALF_UP)
    return int(scaled)


def build_start_payload(total_units: float, duration_minutes: int, immediate_units: Optional[float]) -> bytes:
    if duration_minutes < 0:
        raise ValueError("Duration must be >= 0")
    total_scaled = _scale_insulin(total_units)
    immediate_units = immediate_units if immediate_units is not None else 0
    immediate_scaled = _scale_insulin(immediate_units)
    if immediate_scaled > total_scaled and duration_minutes > 0:
        raise ValueError("Immediate part cannot exceed total bolus")
    bolus_type = 1 if duration_minutes == 0 else 2
    buf = bytearray()
    buf.extend(total_scaled.to_bytes(4, "little"))
    buf.extend(int(duration_minutes).to_bytes(4, "little"))
    buf.extend(immediate_scaled.to_bytes(4, "little"))
    buf.append(bolus_type)
    return bytes(buf)


def build_stop_payload(kind: str) -> bytes:
    mapping = {"fast": 1, "extended": 2, "combined": 2}
    if kind not in mapping:
        raise ValueError("Bolus type must be one of: fast, extended, combined")
    buf = bytearray(13)
    buf[-1] = mapping[kind]
    return bytes(buf)


async def send_bolus_payload(pump: dict, payload: bytes, cryptor: Optional[PumpCryptor]):
    framed = payload + crc16(payload)
    if cryptor:
        framed = cryptor.encrypt(framed)
    frames = chunk_payload(framed)
    async with authenticated_client(pump) as client:
        for frame in frames:
            await client.write_gatt_char(CHAR_BOLUS_START_STOP, frame, response=True)


def build_tbr_start_payload(tbr_percent: int, duration_min: int = 30) -> bytes:
    if not (0 <= tbr_percent <= 200):
        raise ValueError("TBR percent must be between 0 and 200")
    if not (15 <= duration_min <= 1440):
        raise ValueError("TBR duration must be between 15 and 1440 minutes")
    return (
        tbr_percent.to_bytes(4, "little", signed=False)
        + (~tbr_percent & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        + duration_min.to_bytes(4, "little", signed=False)
        + (~duration_min & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
    )


def build_tbr_stop_payload() -> bytes:
    return b"\x00" * 16


async def send_tbr_payload(pump: dict, payload: bytes, cryptor: Optional[PumpCryptor]):
    framed = payload + crc16(payload)
    if cryptor:
        framed = cryptor.encrypt(framed)
    frames = chunk_payload(framed)
    async with authenticated_client(pump) as client:
        for frame in frames:
            await client.write_gatt_char(CHAR_TBR_START_STOP, frame, response=True)


async def write_index_glb(client, uuid: str, value: int, cryptor: Optional[PumpCryptor]):
    payload = create_glb_safe_var(value)
    if cryptor:
        payload = cryptor.encrypt(payload)
    frames = chunk_payload(payload)
    for frame in frames:
        await client.write_gatt_char(uuid, frame, response=True)


async def read_history_entries(client, config: dict, cryptor: Optional[PumpCryptor], warnings: List[str], limit=None):
    count_buf = await read_extended_char(client, config["count_uuid"])
    count_plain = maybe_decrypt("count", count_buf, is_glb_safe_var, cryptor, warnings)
    try:
        total = decode_glb_safe_var(count_plain)
    except ValueError as exc:
        warnings.append(f"count decode failed: {exc}")
        return [], 0
    if total == 0:
        return [], 0
    start_index = 0
    if limit and total > limit:
        start_index = total - limit
    await write_index_glb(client, config["index_uuid"], start_index, cryptor)
    entries = []
    for _ in range(start_index, total):
        raw = await read_extended_char(client, config["value_uuid"])
        raw_plain = maybe_decrypt("entry", raw, crc16_valid, cryptor, warnings)
        if not crc16_valid(raw_plain):
            continue
        payload = raw_plain[:-2]
        entry = parse_entry(payload)
        entry["type_name"] = type_name(entry["type_id"])
        entries.append(entry)
        if limit and len(entries) >= limit:
            break
    return entries, total


def decode_bolus_status(payload: bytes) -> dict:
    if len(payload) < 42:
        raise ValueError(f"Payload bolus trop court ({len(payload)} octets)")
    idx = 0
    fast_status = get_char_value(payload, idx, 1)
    idx += 1
    fast = None
    if fast_status != 0:
        sequence = get_char_value(payload, idx, 4)
        idx += 4
        injected = get_char_value(payload, idx, 4) / 100
        idx += 4
        total = get_char_value(payload, idx, 4) / 100
        idx += 4
        fast = {"status": fast_status, "sequence": sequence, "injected": injected, "total": total}
    idx = 13
    slow_status = get_char_value(payload, idx, 1)
    idx += 1
    slow = None
    if slow_status != 0:
        sequence = get_char_value(payload, idx, 4)
        idx += 4
        injected_slow = get_char_value(payload, idx, 4) / 100
        idx += 4
        total_slow = get_char_value(payload, idx, 4) / 100
        idx += 4
        injected_fast_part = get_char_value(payload, idx, 4) / 100
        idx += 4
        total_fast_part = get_char_value(payload, idx, 4) / 100
        idx += 4
        actual_duration = get_char_value(payload, idx, 4)
        idx += 4
        total_duration = get_char_value(payload, idx, 4)
        slow = {
            "status": slow_status,
            "sequence": sequence,
            "injected_slow": injected_slow,
            "total_slow": total_slow,
            "injected_fast_part": injected_fast_part,
            "total_fast_part": total_fast_part,
            "actual_duration_min": actual_duration,
            "total_duration_min": total_duration,
        }
    return {"fast": fast, "slow": slow}


def decode_system_status(payload: bytes) -> dict:
    if len(payload) < 7:
        raise ValueError(f"Payload système trop court ({len(payload)} octets)")
    delivery_mode = get_char_value(payload, 0, 1)
    insulin_left = get_char_value(payload, 1, 4) / 100
    battery = get_char_value(payload, 5, 1)
    return {"delivery_mode": delivery_mode, "insulin_remaining": insulin_left, "battery": battery}


async def fetch_status(pump: dict, cryptor: Optional[PumpCryptor]) -> dict:
    warnings: List[str] = []
    result = {"warnings": warnings}
    async with authenticated_client(pump) as client:
        bolus_plain = await read_extended_char(client, CHAR_BOLUS_STATUS)
        system_plain = await read_extended_char(client, CHAR_SYSTEM_STATUS)
    if cryptor:
        try:
            bolus_plain = cryptor.decrypt(bolus_plain)
        except Exception as exc:
            warnings.append(f"{CHAR_BOLUS_STATUS}: decrypt error {exc}")
        try:
            system_plain = cryptor.decrypt(system_plain)
        except Exception as exc:
            warnings.append(f"{CHAR_SYSTEM_STATUS}: decrypt error {exc}")
    if not crc16_valid(bolus_plain):
        warnings.append(f"{CHAR_BOLUS_STATUS}: CRC16 invalide")
    else:
        try:
            result["bolus"] = decode_bolus_status(bolus_plain[:-2])
        except Exception as exc:
            result["bolus_error"] = str(exc)
    if not crc16_valid(system_plain):
        warnings.append(f"{CHAR_SYSTEM_STATUS}: CRC16 invalide")
    else:
        try:
            result["system"] = decode_system_status(system_plain[:-2])
        except Exception as exc:
            result["system_error"] = str(exc)
    return result


def find_glb_safe_var(payload: bytes) -> Optional[int]:
    if len(payload) < 8:
        return None
    for start in range(0, len(payload) - 7):
        window = payload[start : start + 8]
        if is_glb_safe_var(window):
            return int.from_bytes(window[0:4], "little")
    return None


async def fetch_basal(pump: dict, cryptor: Optional[PumpCryptor]) -> dict:
    warnings: List[str] = []
    result = {"warnings": warnings}
    async with authenticated_client(pump) as client:
        await write_index_glb(client, "669a0c20-0008-969e-e211-fcbeb3147bc5", 1, cryptor)
        active_raw = await read_extended_char(client, "669a0c20-0008-969e-e211-fcbeb4147bc5")
        if cryptor:
            try:
                active_raw = cryptor.decrypt(active_raw)
            except Exception as exc:
                warnings.append(f"active program decrypt error: {exc}")
        active_val = find_glb_safe_var(active_raw)
        if active_val is None:
            warnings.append(f"Active program decode error, raw={active_raw.hex()}")
            active_name = "UNKNOWN"
        else:
            active_name = "A" if active_val == 3 else ("B" if active_val == 10 else f"UNKNOWN_{active_val}")
        result["active_program"] = active_name

        async def fetch_program(start_idx: int, end_idx: int):
            entries = []
            for idx in range(start_idx, end_idx + 1):
                await write_index_glb(client, "669a0c20-0008-969e-e211-fcbeb3147bc5", idx, cryptor)
                data_raw = await read_extended_char(client, "669a0c20-0008-969e-e211-fcbeb4147bc5")
                if cryptor:
                    try:
                        data_dec = cryptor.decrypt(data_raw)
                    except Exception:
                        data_dec = data_raw
                else:
                    data_dec = data_raw
                rate_centi = find_glb_safe_var(data_dec)
                if rate_centi is None:
                    warnings.append(f"Index {idx}: decode error GLB_SAFE_VAR introuvable, raw={data_dec.hex()}")
                    rate = None
                elif rate_centi == 0xFFFFFFFF:
                    rate = None
                else:
                    rate = rate_centi / 100
                entries.append({"hour": idx - start_idx, "rate_u_per_h": rate})
            return entries

        result["programs"] = {
            "A": await fetch_program(14, 37),
            "B": await fetch_program(38, 61),
        }
    return result


async def fetch_history(pump: dict, cryptor: Optional[PumpCryptor], kind: str, limit=None) -> dict:
    if kind not in ENTRY_CONFIG:
        raise ValueError(f"Type d'historique inconnu: {kind}")
    warnings: List[str] = []
    async with authenticated_client(pump) as client:
        entries, total = await read_history_entries(client, ENTRY_CONFIG[kind], cryptor, warnings, limit=limit)
    return {
        "entries": entries,
        "total": total,
        "warnings": warnings,
    }


async def watch_notifications(
    pump: dict, cryptor: Optional[PumpCryptor], on_event: Callable[[dict], None], timeout: Optional[int] = None
) -> List[str]:
    warnings: List[str] = []

    def callback(_: int, raw: bytearray):
        payload = bytes(raw)
        plain = payload
        if cryptor:
            try:
                plain = cryptor.decrypt(payload)
            except Exception as exc:
                warnings.append(f"decrypt error: {exc}")
        if crc16_valid(plain):
            plain = plain[:-2]
        else:
            warnings.append("CRC16 invalide")
        try:
            event = {
                "fast_status": plain[0],
                "fast_sequence": int.from_bytes(plain[1:5], "little"),
                "slow_status": plain[5],
                "slow_sequence": int.from_bytes(plain[6:10], "little"),
                "timestamp": time.time(),
            }
            on_event(event)
        except Exception as exc:
            warnings.append(f"parse error: {exc}")

    async with authenticated_client(pump) as client:
        await client.start_notify(CHAR_BOLUS_NOTIFICATION, callback)
        try:
            if timeout:
                await asyncio.sleep(timeout)
            else:
                while True:
                    await asyncio.sleep(1)
        finally:
            await client.stop_notify(CHAR_BOLUS_NOTIFICATION)
    return warnings


async def read_versions(client) -> dict:
    out = {}
    for key, uuid in [
        ("master", CHAR_MASTER_VERSION),
        ("base", CHAR_BASE_VERSION),
        ("settings", CHAR_SETTINGS_VERSION),
        ("history", CHAR_HISTORY_VERSION),
    ]:
        data = await client.read_gatt_char(uuid)
        out[key] = data.decode("utf-8").rstrip("\x00")
    return out


def ensure_latest_version(master_version: str):
    if len(master_version) < 3:
        raise RuntimeError(f"Unexpected master version '{master_version}'")
    key = master_version[1:3]
    if key != "05":
        raise RuntimeError(f"Unsupported pump firmware {master_version}. Only latest generation supported.")


def decode_pump_datetime(date_bytes: bytes, time_bytes: bytes):
    year = get_char_value(date_bytes, 0, 2)
    month = get_char_value(date_bytes, 2, 1) or 1
    day = get_char_value(date_bytes, 3, 1) or 1
    hour = get_char_value(time_bytes, 0, 1) if len(time_bytes) > 0 else 0
    minute = get_char_value(time_bytes, 1, 1) if len(time_bytes) > 1 else 0
    second = get_char_value(time_bytes, 2, 1) if len(time_bytes) > 2 else 0
    if year < 2000 or year > 2200:
        raise ValueError(f"Pump date out of range: {year}-{month}-{day}")
    return datetime(year, month, day, hour, minute, second)


async def extract_snapshot(
    data: dict,
    pump: dict,
    cryptor: Optional[PumpCryptor],
    *,
    limit: Optional[int] = None,
) -> dict:
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "serial": pump["serial"],
        "entries": {},
        "warnings": [],
    }
    warnings = output["warnings"]
    async with authenticated_client(pump) as client:
        versions = await read_versions(client)
        ensure_latest_version(versions["master"])
        output["versions"] = versions
        sys_date_raw = await read_extended_char(client, CHAR_SYSTEM_DATE)
        sys_time_raw = await read_extended_char(client, CHAR_SYSTEM_TIME)
        sys_date_plain = maybe_decrypt("system_date", sys_date_raw, lambda b: len(b) >= 4, cryptor, warnings)
        sys_time_plain = maybe_decrypt("system_time", sys_time_raw, lambda b: len(b) >= 3, cryptor, warnings)
        try:
            pump_datetime = decode_pump_datetime(sys_date_plain, sys_time_plain)
            output["pump_datetime"] = pump_datetime.isoformat()
        except ValueError as exc:
            now = datetime.now(timezone.utc)
            warnings.append(str(exc))
            output["pump_datetime"] = now.isoformat()
        output["counts"] = {}
        for name, config in ENTRY_CONFIG.items():
            entries, total = await read_history_entries(client, config, cryptor, warnings, limit=limit)
            output["entries"][name] = entries
            output["counts"][name] = {"total": total, "returned": len(entries)}
    return output
