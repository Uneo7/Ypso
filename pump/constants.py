# ==============================================================================
# SERVICES
# ==============================================================================
SERVICE_BASE = "fb349b5f-8000-0080-0010-0000adde0000"          # Authorization/Base
SERVICE_SETTINGS = "fb349b5f-8000-0080-0010-0000efbe0000"      # Settings
SERVICE_HISTORY = "fb349b5f-8000-0080-0010-0000dec00000"       # History
SERVICE_BOLUS = "fb349b5f-8000-0080-0010-0000feda0000"         # Bolus control
SERVICE_CRYPTO = "fb349b5f-8000-0080-0010-0000feda0002"        # Crypto/Key exchange
SERVICE_FOTA = "fb349b5f-8000-0080-0010-0000feda0003"          # Firmware update
SERVICE_ADVERTISED = "669a0c20-0008-969e-e211-fcff00000002"    # Advertised service

# ==============================================================================
# CHARACTERISTICS - Authorization (SERVICE_BASE)
# ==============================================================================
CHAR_AUTH_PASSWORD = "669a0c20-0008-969e-e211-fcbeb2147bc5"    # Write password (MD5)

# CHAR_AUTH_PASSWORD implements THREE access levels, not a single password.
# BLE_SvcDev_VerifyAuthKey (0x08059616 on V05.00.52) hashes the local BD
# address with each of three 10-byte secrets in turn and records the level
# that matched. Permissions are then looked up PER LEVEL:
# BLE_Prf_InvokeCharCallback reads ctx[0x14 + level], so each characteristic
# has its own permission byte for each level.
#
#   level 3 (0x08036770) - highest; required by the test service's memory
#                          characteristics and by the history-clear one
#   level 2 (0x08036766) - ordinary application access: settings, history,
#                          commands. This is what the SDK used by default.
#   level 1 (0x0803675C) - lowest
#
# With level 2 the memory characteristics answer "Insufficient
# Authorization" — that error comes from the firmware's own per-level
# permission byte, not from the Bluetooth stack.
AUTH_SECRET_L3 = bytes([0x1F, 0x69, 0x84, 0x15, 0xEC, 0x4F, 0xC9, 0x91, 0x1F, 0xA9])
AUTH_SECRET_L2 = bytes([0x4F, 0xC2, 0x45, 0x4D, 0x9B, 0x81, 0x59, 0xA4, 0x93, 0xBB])
AUTH_SECRET_L1 = bytes([0x5B, 0xD7, 0x10, 0x66, 0x01, 0xF2, 0x4F, 0x3C, 0x8F, 0x6B])

AUTH_SALTS = {
    3: AUTH_SECRET_L3,
    2: AUTH_SECRET_L2,
    1: AUTH_SECRET_L1,
    # anciens noms, conservés pour ne pas casser les appelants
    "test": AUTH_SECRET_L3,
    "app": AUTH_SECRET_L2,
}

# Rétrocompatibilité
AUTH_SALT_APP = AUTH_SECRET_L2
AUTH_SALT_TEST = AUTH_SECRET_L3
CHAR_MASTER_VERSION = "669a0c20-0008-969e-e211-fcbeb0147bc5"   # Read master version
CHAR_SUPERVISOR_VERSION = "669a0c20-0008-969e-e211-fcbeb1147bc5"  # Read supervisor version
CHAR_BASE_VERSION = "669a0c20-0008-969e-e211-fcbee23b7bc5"     # Read base service version
CHAR_SETTINGS_VERSION = "669a0c20-0008-969e-e211-fcbee33b7bc5" # Read settings version
CHAR_HISTORY_VERSION = "669a0c20-0008-969e-e211-fcbee43b7bc5"  # Read history version

# ==============================================================================
# CHARACTERISTICS - Settings (SERVICE_SETTINGS)
# ==============================================================================
CHAR_SETTINGS_ID = "669a0c20-0008-969e-e211-fcbeb3147bc5"      # Settings ID
CHAR_SETTINGS_VALUE = "669a0c20-0008-969e-e211-fcbeb4147bc5"   # Settings value

# ==============================================================================
# CHARACTERISTICS - System (SERVICE_BASE)
# ==============================================================================
CHAR_SYSTEM_DATE = "669a0c20-0008-969e-e211-fcbedc3b7bc5"      # Read/Write date
CHAR_SYSTEM_TIME = "669a0c20-0008-969e-e211-fcbedd3b7bc5"      # Read/Write time
CHAR_SYSTEM_STATUS = "669a0c20-0008-969e-e211-fcbee48b7bc5"    # Read system status

# ==============================================================================
# CHARACTERISTICS - Bolus (SERVICE_BOLUS)
# ==============================================================================
CHAR_BOLUS_START_STOP = "669a0c20-0008-969e-e211-fcbee18b7bc5" # Start/Stop bolus
CHAR_BOLUS_STATUS = "669a0c20-0008-969e-e211-fcbee28b7bc5"     # Read bolus status
CHAR_TBR_START_STOP = "669a0c20-0008-969e-e211-fcbee38b7bc5"   # Start/Stop TBR
CHAR_BOLUS_NOTIFICATION = "669a0c20-0008-969e-e211-fcbee58b7bc5"  # Bolus notifications (notify)

# ==============================================================================
# CHARACTERISTICS - Crypto/Key Exchange (SERVICE_CRYPTO)
# ==============================================================================
CHAR_REQUEST_PUBLIC_KEY = "669a0c20-0008-969e-e211-fcff0000000a"  # Read challenge + pump pubkey
CHAR_WRITE_CHALLENGE = "669a0c20-0008-969e-e211-fcff0000000b"     # Write 116 bytes response
CHAR_EXTENDED_READ = "669a0c20-0008-969e-e211-fcff000000ff"       # Extended read (multi-frame)
CHAR_VIRTUAL = "669a0c20-0008-969e-e211-ffffffffffff"             # Virtual characteristic

# ==============================================================================
# CHARACTERISTICS - History Entries (SERVICE_HISTORY)
# ==============================================================================
ENTRY_CONFIG = {
    "events": {
        "count_uuid": "669a0c20-0008-969e-e211-fcbecb3b7bc5",
        "index_uuid": "669a0c20-0008-969e-e211-fcbecc3b7bc5",
        "value_uuid": "669a0c20-0008-969e-e211-fcbecd3b7bc5",
    },
    "alerts": {
        "count_uuid": "669a0c20-0008-969e-e211-fcbec83b7bc5",
        "index_uuid": "669a0c20-0008-969e-e211-fcbec93b7bc5",
        "value_uuid": "669a0c20-0008-969e-e211-fcbeca3b7bc5",
    },
    "system": {
        "count_uuid": "86a5a431-d442-2c8d-304b-19ee355571fc",
        "index_uuid": "381ddce9-e934-b4ae-e345-eb87283db426",
        "value_uuid": "ae3022af-2ec8-bf88-e64c-da68c9a3891a",
    },
    "complaints": {
        "count_uuid": "449753d3-3cc5-7594-ae4f-8d4efa2af4fd",
        "index_uuid": "db75669b-e6cc-f6a4-1f4b-0becaeb81f34",
        "value_uuid": "813a4e12-e1e2-47a0-2544-22664b3c9e62",
    },
}

# ==============================================================================
# BLE ERROR CODES (from CBATTErrorDomain / pump firmware)
# ==============================================================================
BLE_ERRORS = {
    1: "Invalid Handle",
    2: "Read not permitted",
    3: "Write not permitted",
    4: "Invalid PDU",
    5: "Insufficient Authentication",
    8: "Insufficient Authorization (password not sent or wrong)",
    10: "Attribute not found",
    11: "Attribute not long",
    13: "Invalid attribute value length",
    15: "Insufficient encryption",
    16: "Unsupported group type",
    126: "Shared key not valid (BLE read)",
    128: "Application error first",
    129: "Value corrupt",
    130: "Value invalid",
    131: "Invalid ID",
    132: "Entry index invalid",
    133: "Wrong password",
    134: "Shared key not valid (internal error)",
    135: "Command failed",
    136: "Temporarily blocked (5 min cooldown after key exchange, or pump busy)",
    137: "Not ready (wait 45 sec after power-on)",
    138: "Decrypt error (counter mismatch, do a read first to sync)",
    139: "Counter error",
    140: "No shared keys",
    141: "Fragmentation error",
}

EVENT_NAMES = {name: value for name, value in {
    "BOLUS_DELAYED_RUNNING": 1,
    "BOLUS_IMMEDIATE": 2,
    "BOLUS_DELAYED": 3,
    "PRIMING_FINISHED": 4,
    "BOLUS_STEP_CHANGED": 5,
    "BASAL_PROFILE_CHANGED": 6,
    "BASAL_PROFILE_A_CHANGED": 7,
    "BASAL_PROFILE_B_CHANGED": 8,
    "BASAL_PROFILE_TEMP_RUNNING": 9,
    "BASAL_PROFILE_TEMP": 10,
    "DATE_CHANGED": 12,
    "TIME_CHANGED": 13,
    "PUMP_MODE_CHANGED": 14,
    "REWIND_FINISHED": 16,
    "BOLUS_COMBINED_RUNNING": 17,
    "BOLUS_COMBINED": 18,
    "BOLUS_IMMEDIATE_RUNNING": 19,
    "BOLUS_DELAYED_BACKUP": 20,
    "BOLUS_COMBINED_BACKUP": 21,
    "BASAL_PROFILE_TEMP_BACKUP": 22,
    "DAILY_TOTAL_INSULIN": 23,
    "BATTERY_REMOVED": 24,
    "CANNULA_PRIMING_FINISHED": 25,
    "BOLUS_BLIND": 26,
    "BOLUS_BLIND_RUNNING": 27,
    "BOLUS_BLIND_ABORT": 28,
    "BOLUS_IMMEDIATE_ABORT": 29,
    "BOLUS_DELAYED_ABORT": 30,
    "BOLUS_COMBINED_ABORT": 31,
    "BASAL_PROFILE_TEMP_ABORT": 32,
    "BOLUS_AMOUNT_CAP_CHANGED": 33,
    "BASAL_RATE_CAP_CHANGED": 34,
    "A_BATTERY_REMOVED": 100,
    "A_BATTERY_EMPTY": 101,
    "A_REUSABLE_ERROR": 102,
    "A_NO_CARTRIDGE": 103,
    "A_CARTRIDGE_EMPTY": 104,
    "A_OCCLUSION": 105,
    "A_AUTO_STOP": 106,
    "A_LIPO_DISCHARGED": 107,
    "A_BATTERY_REJECTED": 108,
    "DELIVERY_STATUS_CHANGED": 150,
}.items()}

