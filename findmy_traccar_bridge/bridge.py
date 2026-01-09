import datetime
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import TypedDict

import requests
from findmy import KeyPair, FindMyAccessory
from findmy.reports import (
    AppleAccount,
    LoginState,
    LocalAnisetteProvider,
    RemoteAnisetteProvider,
    SmsSecondFactorMethod,
    TrustedDeviceSecondFactorMethod,
)
from loguru import logger

logger.remove()
logger.add(sys.stderr, level=os.environ.get("BRIDGE_LOGGING_LEVEL", "INFO"))

POLLING_INTERVAL = int(os.environ.get("BRIDGE_POLL_INTERVAL", 60 * 60))

# Auto-create devices in Traccar (opt-in)
AUTO_CREATE_DEVICES = os.environ.get("BRIDGE_AUTO_CREATE_DEVICES", "").lower() in ("true", "1", "yes")
TRACCAR_API_URL = os.environ.get("BRIDGE_TRACCAR_API", "")  # e.g., http://traccar:8082
TRACCAR_API_USER = os.environ.get("BRIDGE_TRACCAR_USER", "")
TRACCAR_API_PASS = os.environ.get("BRIDGE_TRACCAR_PASS", "")


data_folder = Path("./data/")
data_folder.mkdir(exist_ok=True)
persistent_data_store = data_folder / "persistent_data.json"
acc_store = data_folder / "account.json"
anisette_libs_store = data_folder / "ani_libs.bin"


# Battery level mapping from status byte (bits 6-7)
BATTERY_LEVELS = {
    0b00: 100,  # Full
    0b01: 75,   # Medium
    0b10: 50,   # Low
    0b11: 25,   # Very Low
}

BATTERY_NAMES = {
    0b00: "Full",
    0b01: "Medium",
    0b10: "Low",
    0b11: "Very Low",
}


def get_battery_level(status: int) -> tuple[int, str]:
    """Extract battery level from location report status byte."""
    battery_id = (status >> 6) & 0b11
    return BATTERY_LEVELS.get(battery_id, 0), BATTERY_NAMES.get(battery_id, "Unknown")


# Cache of devices already created in Traccar (to avoid repeated API calls)
_created_devices: set[int] = set()


def create_traccar_device(traccar_id: int, name: str) -> bool:
    """
    Create a device in Traccar via the REST API.

    Args:
        traccar_id: The unique identifier for the device
        name: Human-readable name for the device

    Returns:
        True if device was created successfully or already exists, False otherwise
    """
    if not AUTO_CREATE_DEVICES:
        return False

    if traccar_id in _created_devices:
        return True

    if not TRACCAR_API_URL or not TRACCAR_API_USER or not TRACCAR_API_PASS:
        logger.warning(
            "Auto-create devices enabled but BRIDGE_TRACCAR_API, BRIDGE_TRACCAR_USER, "
            "or BRIDGE_TRACCAR_PASS not set"
        )
        return False

    api_url = TRACCAR_API_URL.rstrip("/")

    try:
        # First check if device already exists
        resp = requests.get(
            f"{api_url}/api/devices",
            auth=(TRACCAR_API_USER, TRACCAR_API_PASS),
            timeout=30,
        )
        if resp.status_code == 200:
            devices = resp.json()
            for device in devices:
                if str(device.get("uniqueId")) == str(traccar_id):
                    logger.debug("Device {} already exists in Traccar", traccar_id)
                    _created_devices.add(traccar_id)
                    return True

        # Create the device
        resp = requests.post(
            f"{api_url}/api/devices",
            auth=(TRACCAR_API_USER, TRACCAR_API_PASS),
            json={
                "name": name,
                "uniqueId": str(traccar_id),
            },
            timeout=30,
        )

        if resp.status_code == 200:
            logger.info("Created device in Traccar: {} (ID: {})", name, traccar_id)
            _created_devices.add(traccar_id)
            return True
        else:
            logger.warning(
                "Failed to create device {} in Traccar: {} {}",
                traccar_id,
                resp.status_code,
                resp.text,
            )
            return False

    except requests.RequestException as e:
        logger.error("Error communicating with Traccar API: {}", e)
        return False


class Location(TypedDict):
    id: int
    timestamp: int
    lat: float
    lon: float
    batt: int  # Battery percentage (0-100)
    accuracy: int  # Horizontal accuracy in meters


class PersistentData(TypedDict):
    # rejected locations by traccar (id has not been claimed by a user), will keep retrying to upload these
    pending_locations: list[Location]
    # recently uploaded locations used for deduplication
    uploaded_locations: list[Location]
    # unix timestamp
    last_apple_api_call: int


if not persistent_data_store.is_file():
    persistent_data_store.write_text(
        json.dumps(
            PersistentData(
                pending_locations=[],
                uploaded_locations=[],
                last_apple_api_call=0,
            )
        )
    )


def commit(persistent_data: PersistentData) -> None:
    persistent_data_store.write_text(json.dumps(persistent_data))


def load_airtags_from_directory(directory_path: str | None) -> list[FindMyAccessory]:
    """
    Load all FindMyAccessory objects from .plist files in the specified directory.
    
    Args:
        directory_path: Path to the directory containing .plist files
        
    Returns:
        List of loaded FindMyAccessory objects
    """
    if not directory_path:
        return []
        
    airtags = []
    dir_path = Path(directory_path)
    
    if not dir_path.exists():
        # Only log as error if it's not the default path
        if directory_path != "/bridge/plists":
            logger.error("Plist directory does not exist: {}", directory_path)
        return []
    
    if not dir_path.is_dir():
        logger.error("Plist path exists but is not a directory: {}", directory_path)
        return []
        
    plist_files = list(dir_path.glob("*.plist"))
    for plist_path in plist_files:
        try:
            with plist_path.open("rb") as f:
                airtags.append(FindMyAccessory.from_plist(f))
        except Exception as e:
            logger.error("Failed to load plist file {}: {}", plist_path, str(e))
            
    return airtags


def load_airtags_from_json_directory(directory_path: str | None) -> tuple[list[FindMyAccessory], dict[FindMyAccessory, Path]]:
    """
    Load FindMyAccessory objects from .json key files in the specified directory.

    Args:
        directory_path: Path to the directory containing .json key files

    Returns:
        Tuple of (list of accessories, dict mapping accessory to its file path)
    """
    if not directory_path:
        return [], {}

    airtags = []
    airtag_paths: dict[FindMyAccessory, Path] = {}
    dir_path = Path(directory_path)

    if not dir_path.exists():
        # Only log as error if it's not the default path
        if directory_path != "/bridge/json_keys":
            logger.error("JSON keys directory does not exist: {}", directory_path)
        return [], {}

    if not dir_path.is_dir():
        logger.error("JSON keys path is not a directory: {}", directory_path)
        return [], {}

    for json_path in dir_path.glob("*.json"):
        try:
            airtag = FindMyAccessory.from_json(json_path)
            airtags.append(airtag)
            airtag_paths[airtag] = json_path
            logger.debug("Loaded JSON key file: {}", json_path.name)
        except Exception as e:
            logger.error("Failed to load JSON key file {}: {}", json_path, str(e))

    return airtags, airtag_paths


def create_account() -> AppleAccount:
    """
    Create an AppleAccount with appropriate anisette provider.
    Uses LocalAnisetteProvider if BRIDGE_ANISETTE_SERVER is not set (recommended).
    """
    anisette_server = os.environ.get("BRIDGE_ANISETTE_SERVER")

    if anisette_server:
        logger.info("Using remote anisette server: {}", anisette_server)
        anisette = RemoteAnisetteProvider(anisette_server)
    else:
        logger.info("Using built-in local anisette provider")
        anisette = LocalAnisetteProvider(libs_path=str(anisette_libs_store))

    return AppleAccount(anisette)


def load_account() -> AppleAccount:
    """Load account from JSON store."""
    anisette_server = os.environ.get("BRIDGE_ANISETTE_SERVER")
    libs_path = None if anisette_server else str(anisette_libs_store)
    try:
        return AppleAccount.from_json(acc_store, anisette_libs_path=libs_path)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        logger.error("Failed to load account (may be old format): {}", e)
        logger.error("Please delete {} and re-run findmy-traccar-bridge-init", acc_store)
        raise


def bridge() -> None:
    """
    Main loop fetching location data from the Apple API and forwarding it to a Traccar server.

    Callable via the binary `.venv/bin/findmy-traccar-bridge`
    """

    private_keys = [k for k in (os.environ.get("BRIDGE_PRIVATE_KEYS") or "").split(",") if k]

    # Directory locations
    plist_dir = os.environ.get("BRIDGE_PLIST_DIR", "/bridge/plists")
    json_dir = os.environ.get("BRIDGE_JSON_DIR", "/bridge/json_keys")

    haystack_keys = [KeyPair.from_b64(key) for key in private_keys]
    plist_airtags = load_airtags_from_directory(plist_dir)
    json_airtags, json_airtag_paths = load_airtags_from_json_directory(json_dir)
    real_airtags = plist_airtags + json_airtags

    if not private_keys and not real_airtags:
        raise ValueError(
            "No tracking devices configured. Options:\n"
            "  1. Set BRIDGE_PRIVATE_KEYS env var (Haystack beacons)\n"
            "  2. Mount .plist files to /bridge/plists (or set BRIDGE_PLIST_DIR)\n"
            "  3. Mount .json key files to /bridge/json_keys (or set BRIDGE_JSON_DIR)"
        )

    logger.info("Loaded {} plist AirTags, {} JSON AirTags", len(plist_airtags), len(json_airtags))

    TRACCAR_SERVER = os.environ["BRIDGE_TRACCAR_SERVER"]

    logger.info("Target Traccar server: {}", TRACCAR_SERVER)

    if not acc_store.is_file():
        logger.info(
            "Login token file not found at '{}'. You must first generate it interactively via "
            "`docker compose exec bridge .venv/bin/findmy-traccar-bridge-init`",
            str(acc_store),
        )
        while not acc_store.is_file():
            time.sleep(1)

    acc = load_account()
    logger.info("Successfully loaded Apple account")

    logger.info("Configured {} device{}:",
                len(haystack_keys) + len(real_airtags),
                "" if len(haystack_keys) + len(real_airtags) == 1 else "s")
    for key in haystack_keys:
        logger.info(
            "   Haystack device\t| Private key: {}[...]\t\t|\tTraccar ID {}",
            key.hashed_adv_key_b64[:16],
            int.from_bytes(key.hashed_adv_key_bytes) % 1_000_000
        )
    for airtag in real_airtags:
        identifier = airtag.identifier or airtag.name or "unknown"
        display_name = airtag.name or airtag.identifier or "unknown"
        traccar_id = int.from_bytes(identifier.encode()[:8], 'big') % 1_000_000
        logger.info(
            "   FindMy device\t\t| {}: {}[...]\t|\tTraccar ID {}",
            "name" if airtag.name else "identifier",
            display_name[:16],
            traccar_id
        )

    # Build device name mapping for auto-create feature
    device_names: dict[int, str] = {}
    for key in haystack_keys:
        tid = int.from_bytes(key.hashed_adv_key_bytes) % 1_000_000
        device_names[tid] = f"Haystack {key.hashed_adv_key_b64[:8]}"
    for airtag in real_airtags:
        identifier = airtag.identifier or airtag.name or "unknown"
        tid = int.from_bytes(identifier.encode()[:8], 'big') % 1_000_000
        device_names[tid] = airtag.name or airtag.identifier or f"AirTag {tid}"

    # Proactively create all devices in Traccar at startup
    if AUTO_CREATE_DEVICES:
        logger.info("Ensuring all devices exist in Traccar...")
        for tid, name in device_names.items():
            create_traccar_device(tid, name)

    persistent_data: PersistentData = json.loads(persistent_data_store.read_text())
    last_traccar_push_timestamp = 0  # not super important, so not persistent

    logger.info(
        "Next Apple API polling in {} seconds ({} UTC)",
        time_until_next := max(
            0,
            int(
                -(
                    datetime.datetime.now().timestamp()
                    - persistent_data["last_apple_api_call"]
                    - POLLING_INTERVAL
                )
            ),
        ),
        (
            datetime.datetime.now() + datetime.timedelta(seconds=time_until_next)
        ).isoformat(timespec="seconds"),
    )

    while True:
        # avoid calling the API too often, otherwise the account might be banned
        # also makes sure to respect the interval if the process just restarted (e.g. in a bootloop)
        time_until_next_apple_polling = -(
            datetime.datetime.now().timestamp()
            - persistent_data["last_apple_api_call"]
            - POLLING_INTERVAL
        )
        time_until_next_traccar_push = -(
            datetime.datetime.now().timestamp() - last_traccar_push_timestamp - 30
        )

        if time_until_next_apple_polling > 0 and time_until_next_traccar_push > 0:
            # sleep short durations so that SIGTERM stops the container
            time.sleep(1)
        elif time_until_next_apple_polling <= 0:
            already_uploaded = {
                (location["id"], location["timestamp"])
                for location in persistent_data["uploaded_locations"]
            }
            already_pending = {
                (location["id"], location["timestamp"])
                for location in persistent_data["pending_locations"]
            }

            # Fetch location history using new API
            all_devices = haystack_keys + real_airtags
            reports_dict = acc.fetch_location_history(all_devices) if all_devices else {}

            persistent_data["last_apple_api_call"] = int(
                datetime.datetime.now().timestamp()
            )
            commit(persistent_data)

            for device, reports in reports_dict.items():
                if not reports:
                    continue

                # Determine Traccar ID based on device type
                if isinstance(device, FindMyAccessory):
                    identifier = device.identifier or device.name or str(id(device))
                    traccar_id = int.from_bytes(identifier.encode()[:8], 'big') % 1_000_000
                    shorthand = (device.name or device.identifier or "accessory")[:16]
                else:
                    # Haystack device - use hashed key
                    traccar_id = int.from_bytes(device.hashed_adv_key_bytes) % 1_000_000
                    shorthand = device.hashed_adv_key_b64[:8]

                logger.info(
                    "Received {} locations from device:{} ({})",
                    len(reports),
                    traccar_id,
                    shorthand,
                )

                for report in reports:
                    # Extract battery level
                    battery_pct, battery_name = get_battery_level(report.status)

                    new_location = Location(
                        id=traccar_id,
                        lat=report.latitude,
                        lon=report.longitude,
                        timestamp=int(report.timestamp.timestamp()),
                        batt=battery_pct,
                        accuracy=report.horizontal_accuracy,
                    )

                    loc_key = (new_location["id"], new_location["timestamp"])
                    if loc_key not in already_uploaded and loc_key not in already_pending:
                        persistent_data["pending_locations"].append(new_location)

                logger.debug(
                    "Queued locations from device:{} ({}) for upload",
                    traccar_id,
                    shorthand,
                )

            # Save JSON accessory state (alignment data)
            for airtag, path in json_airtag_paths.items():
                try:
                    airtag.to_json(path)
                except Exception as e:
                    logger.debug("Could not save accessory state to {}: {}", path, e)

            # Save account state (may include refreshed tokens)
            acc.to_json(acc_store)

            logger.info(
                "Next Apple API polling in {} seconds ({} UTC)",
                int(
                    -(
                        datetime.datetime.now().timestamp()
                        - persistent_data["last_apple_api_call"]
                        - POLLING_INTERVAL
                    )
                ),
                datetime.datetime.fromtimestamp(
                    persistent_data["last_apple_api_call"] + POLLING_INTERVAL
                ).isoformat(timespec="seconds"),
            )

            commit(persistent_data)

        elif time_until_next_traccar_push <= 0:
            if (count_locations := len(persistent_data["pending_locations"])) > 0:
                logger.info(
                    "Uploading {} locations to traccar ({})",
                    count_locations,
                    TRACCAR_SERVER,
                )

            failed_upload_locations = []

            for location in persistent_data["pending_locations"]:
                resp = requests.post(
                    TRACCAR_SERVER,
                    data=location,
                )

                if resp.status_code == 200:
                    persistent_data["uploaded_locations"].append(location)
                elif 400 <= resp.status_code < 500:
                    # Client error - device likely doesn't exist in Traccar
                    device_id = location["id"]
                    device_name = device_names.get(device_id, f"FindMy Device {device_id}")

                    if create_traccar_device(device_id, device_name):
                        # Retry the upload after creating the device
                        retry_resp = requests.post(TRACCAR_SERVER, data=location)
                        if retry_resp.status_code == 200:
                            persistent_data["uploaded_locations"].append(location)
                        else:
                            logger.warning(
                                "Upload ({}, {}) failed after device creation: {}",
                                location["id"],
                                location["timestamp"],
                                retry_resp.status_code,
                            )
                            failed_upload_locations.append(location)
                    else:
                        # Auto-create not enabled or failed - queue for retry
                        failed_upload_locations.append(location)
                else:
                    logger.warning(
                        "Upload ({}, {}) failed with code {}",
                        location["id"],
                        location["timestamp"],
                        resp.status_code,
                    )
                    logger.debug("API returned {}", resp.text)
                    failed_upload_locations.append(location)

            unique_failed_devices = {
                location["id"] for location in failed_upload_locations
            }
            if len(unique_failed_devices) > 0:
                if AUTO_CREATE_DEVICES:
                    logger.warning(
                        "Failed to upload locations for devices {}. Auto-create may have failed. "
                        "Reupload will be attempted.",
                        unique_failed_devices,
                    )
                else:
                    logger.warning(
                        "Failed to upload locations for devices {}. They may need to be claimed in the Traccar UI, "
                        "or enable BRIDGE_AUTO_CREATE_DEVICES. Reupload will be attempted.",
                        unique_failed_devices,
                    )

            persistent_data["pending_locations"] = failed_upload_locations

            # Prune old uploaded_locations to prevent unbounded growth
            # Keep only locations newer than 2x polling interval for deduplication
            cutoff = int(datetime.datetime.now().timestamp()) - (POLLING_INTERVAL * 2)
            persistent_data["uploaded_locations"] = [
                loc for loc in persistent_data["uploaded_locations"]
                if loc["timestamp"] > cutoff
            ]

            last_traccar_push_timestamp = datetime.datetime.now().timestamp()

            commit(persistent_data)


def init() -> None:
    """
    One-time interactive login procedure to answer 2fa challenge and generate API token.

    Callable via the binary `.venv/bin/findmy-traccar-bridge-init`
    """
    acc = create_account()

    email = input("email?  > ")
    password = getpass.getpass("passwd? > ")

    state = acc.login(email, password)

    if state == LoginState.REQUIRE_2FA:
        methods = acc.get_2fa_methods()

        for i, method in enumerate(methods):
            if isinstance(method, TrustedDeviceSecondFactorMethod):
                print(f"{i} - Trusted Device")
            elif isinstance(method, SmsSecondFactorMethod):
                print(f"{i} - SMS ({method.phone_number})")

        ind = int(input("Method? > "))

        method = methods[ind]
        method.request()
        code = getpass.getpass("Code? > ")

        method.submit(code)

    # Use new persistence API
    acc.to_json(acc_store)
