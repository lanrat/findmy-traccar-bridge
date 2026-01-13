"""FindMy to Traccar bridge - main entry point."""

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
    SmsSecondFactorMethod,
    TrustedDeviceSecondFactorMethod,
)
from loguru import logger

# Import logging config first to set up logging before other modules
from findmy_traccar_bridge import logging_config  # noqa: F401

# Import from refactored modules
from findmy_traccar_bridge.accounts import (
    create_account,
    discover_accounts,
    get_account_store,
    load_account,
    migrate_legacy_account,
)
from findmy_traccar_bridge.devices import (
    get_battery_level,
    load_airtags_from_directory,
    load_airtags_from_json_directory,
)
from findmy_traccar_bridge.traccar import (
    AUTO_CREATE_DEVICES,
    Location,
    create_traccar_device,
)


POLLING_INTERVAL = int(os.environ.get("BRIDGE_POLL_INTERVAL", 60 * 60))

# Optional: Report location accuracy to Traccar (default: false)
REPORT_ACCURACY = os.environ.get("BRIDGE_REPORT_ACCURACY", "").lower() in (
    "true",
    "1",
    "yes",
)

# Persistent data storage
data_folder = Path("./data/")
data_folder.mkdir(exist_ok=True)
persistent_data_store = data_folder / "persistent_data.json"


class PersistentData(TypedDict):
    """Persistent state for the bridge."""

    # rejected locations by traccar (id has not been claimed by a user), will keep retrying to upload these
    pending_locations: list[Location]
    # recently uploaded locations used for deduplication
    uploaded_locations: list[Location]
    # per-account last poll timestamps: {"0": 123456, "1": 123457}
    account_last_poll: dict[str, int]
    # per-device last uploaded timestamp: {"123456": 1704567890}
    # prevents re-uploading stale locations after pruning
    device_last_timestamp: dict[str, int]


def init_persistent_data() -> None:
    """Initialize persistent data store if it doesn't exist."""
    if not persistent_data_store.is_file():
        persistent_data_store.write_text(
            json.dumps(
                PersistentData(
                    pending_locations=[],
                    uploaded_locations=[],
                    account_last_poll={},
                    device_last_timestamp={},
                )
            )
        )
    else:
        # Migrate old format if needed
        data = json.loads(persistent_data_store.read_text())
        modified = False

        if "account_last_poll" not in data:
            # Migrate from old single-account format
            data["account_last_poll"] = {}
            if "last_apple_api_call" in data:
                # Move old timestamp to account 0
                data["account_last_poll"]["0"] = data.pop("last_apple_api_call")
            modified = True

        if "device_last_timestamp" not in data:
            # First run after upgrade: initialize empty, first poll will upload all historical data once
            data["device_last_timestamp"] = {}
            modified = True

        if modified:
            persistent_data_store.write_text(json.dumps(data))


def commit(persistent_data: PersistentData) -> None:
    """Save persistent data to disk."""
    persistent_data_store.write_text(json.dumps(persistent_data))


def bridge() -> None:
    """
    Main loop fetching location data from the Apple API and forwarding it to a Traccar server.

    Callable via the binary `.venv/bin/findmy-traccar-bridge`
    """
    # Migrate legacy single-account if needed
    migrate_legacy_account()
    init_persistent_data()

    private_keys = [
        k for k in (os.environ.get("BRIDGE_PRIVATE_KEYS") or "").split(",") if k
    ]

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

    logger.info(
        "Loaded {} plist AirTags, {} JSON AirTags", len(plist_airtags), len(json_airtags)
    )

    TRACCAR_SERVER = os.environ["BRIDGE_TRACCAR_SERVER"]

    logger.info("Target Traccar server: {}", TRACCAR_SERVER)

    # Discover and load all accounts
    account_ids = discover_accounts()

    if not account_ids:
        logger.info(
            "No accounts found. You must first initialize at least one account via "
            "`docker compose exec bridge .venv/bin/findmy-traccar-bridge-init`"
        )
        # Wait for at least one account to be initialized
        while not account_ids:
            time.sleep(1)
            account_ids = discover_accounts()

    accounts: dict[int, AppleAccount] = {}
    account_names: dict[int, str] = {}  # account_id -> display name for logging
    for account_id in account_ids:
        try:
            acc = load_account(account_id)
            accounts[account_id] = acc
            account_names[account_id] = acc.account_name or f"account_{account_id}"
            logger.info(
                "Loaded Apple account {}: {}", account_id, account_names[account_id]
            )
        except Exception as e:
            logger.error("Failed to load account {}: {}", account_id, e)

    if not accounts:
        raise RuntimeError("No accounts could be loaded")

    num_accounts = len(accounts)
    effective_interval = POLLING_INTERVAL / num_accounts

    logger.info(
        "Loaded {} account{} - effective update interval: {:.0f} seconds",
        num_accounts,
        "" if num_accounts == 1 else "s",
        effective_interval,
    )

    logger.info(
        "Configured {} device{}:",
        len(haystack_keys) + len(real_airtags),
        "" if len(haystack_keys) + len(real_airtags) == 1 else "s",
    )
    for key in haystack_keys:
        logger.info(
            "   Haystack device | Traccar ID {} | Key: {}",
            int.from_bytes(key.hashed_adv_key_bytes) % 1_000_000,
            key.hashed_adv_key_b64,
        )
    for airtag in real_airtags:
        identifier = airtag.identifier or airtag.name or "unknown"
        display_name = airtag.name or airtag.identifier or "unknown"
        traccar_id = int.from_bytes(identifier.encode()[:8], "big") % 1_000_000
        logger.info(
            "   FindMy device   | Traccar ID {} | Name: {} | ID: {}",
            traccar_id,
            display_name,
            airtag.identifier or "(none)",
        )

    # Build device name and identifier mappings
    device_names: dict[int, str] = {}
    device_identifiers: dict[int, str] = {}  # Full identifier for Traccar attributes
    for key in haystack_keys:
        tid = int.from_bytes(key.hashed_adv_key_bytes) % 1_000_000
        device_names[tid] = f"Haystack {key.hashed_adv_key_b64[:8]}"
        device_identifiers[tid] = key.hashed_adv_key_b64  # Full hashed key
    for airtag in real_airtags:
        identifier = airtag.identifier or airtag.name or "unknown"
        tid = int.from_bytes(identifier.encode()[:8], "big") % 1_000_000
        device_names[tid] = airtag.name or airtag.identifier or f"AirTag {tid}"
        if airtag.identifier:
            device_identifiers[tid] = airtag.identifier

    # Proactively create all devices in Traccar at startup
    if AUTO_CREATE_DEVICES:
        logger.info("Ensuring all devices exist in Traccar...")
        for tid, name in device_names.items():
            create_traccar_device(tid, name)

    persistent_data: PersistentData = json.loads(persistent_data_store.read_text())
    last_traccar_push_timestamp = 0.0

    # Round-robin account polling
    account_order = sorted(accounts.keys())  # deterministic order

    # On startup, find which account to start with (the one polled longest ago)
    def find_oldest_account_index() -> int:
        oldest_idx = 0
        oldest_time = persistent_data["account_last_poll"].get(str(account_order[0]), 0)
        for i, aid in enumerate(account_order):
            last_poll = persistent_data["account_last_poll"].get(str(aid), 0)
            if last_poll < oldest_time:
                oldest_time = last_poll
                oldest_idx = i
        return oldest_idx

    current_account_index = find_oldest_account_index()

    def get_next_account_to_poll() -> tuple[int, float]:
        """Get the next account in round-robin order and how long to wait."""
        now = datetime.datetime.now().timestamp()

        # Find when any account was last polled (for spacing)
        all_last_polls = [
            persistent_data["account_last_poll"].get(str(aid), 0) for aid in accounts
        ]
        last_any_poll = max(all_last_polls) if all_last_polls else 0
        wait_time = max(0, effective_interval - (now - last_any_poll))

        return (account_order[current_account_index], wait_time)

    def advance_to_next_account() -> None:
        """Move to the next account in round-robin order."""
        nonlocal current_account_index
        current_account_index = (current_account_index + 1) % len(account_order)

    # Log initial status
    account_id, wait_time = get_next_account_to_poll()
    logger.info(
        "Next Apple API polling (account {} - {}) in {:.0f} seconds ({} UTC)",
        account_id,
        account_names.get(account_id, "unknown"),
        wait_time,
        (
            datetime.datetime.now() + datetime.timedelta(seconds=wait_time)
        ).isoformat(timespec="seconds"),
    )

    while True:
        account_to_poll, time_until_next_apple_polling = get_next_account_to_poll()
        time_until_next_traccar_push = -(
            datetime.datetime.now().timestamp() - last_traccar_push_timestamp - 30
        )

        if time_until_next_apple_polling > 0 and time_until_next_traccar_push > 0:
            # sleep short durations so that SIGTERM stops the container
            time.sleep(1)
        elif time_until_next_apple_polling <= 0:
            acc = accounts[account_to_poll]
            acc_store = get_account_store(account_to_poll)

            logger.info(
                "Polling Apple API with account {} ({})...",
                account_to_poll,
                account_names.get(account_to_poll, "unknown"),
            )

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
            try:
                reports_dict = (
                    acc.fetch_location_history(all_devices) if all_devices else {}
                )
            except Exception as e:
                logger.error(
                    "Failed to fetch locations with account {} ({}): {}",
                    account_to_poll,
                    account_names.get(account_to_poll, "unknown"),
                    e,
                )
                # Still update last poll time to avoid hammering on errors
                persistent_data["account_last_poll"][str(account_to_poll)] = int(
                    datetime.datetime.now().timestamp()
                )
                commit(persistent_data)
                advance_to_next_account()
                continue

            persistent_data["account_last_poll"][str(account_to_poll)] = int(
                datetime.datetime.now().timestamp()
            )
            commit(persistent_data)

            for device, reports in reports_dict.items():
                if not reports:
                    continue

                # Determine Traccar ID based on device type
                if isinstance(device, FindMyAccessory):
                    identifier = device.identifier or device.name or str(id(device))
                    traccar_id = (
                        int.from_bytes(identifier.encode()[:8], "big") % 1_000_000
                    )
                    shorthand = (device.name or device.identifier or "accessory")[:16]
                else:
                    # Haystack device - use hashed key
                    traccar_id = int.from_bytes(device.hashed_adv_key_bytes) % 1_000_000
                    shorthand = device.hashed_adv_key_b64[:8]

                logger.info(
                    "Received {} locations from device:{} ({}) via account {}",
                    len(reports),
                    traccar_id,
                    shorthand,
                    account_to_poll,
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
                    device_id_str = str(new_location["id"])
                    last_ts = persistent_data["device_last_timestamp"].get(
                        device_id_str, 0
                    )

                    # Only queue if timestamp is newer than last uploaded for this device
                    if new_location["timestamp"] > last_ts:
                        if (
                            loc_key not in already_uploaded
                            and loc_key not in already_pending
                        ):
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

            # Advance to next account in round-robin
            advance_to_next_account()

            # Log next poll info
            next_account, next_wait = get_next_account_to_poll()
            logger.info(
                "Next Apple API polling (account {} - {}) in {:.0f} seconds ({} UTC)",
                next_account,
                account_names.get(next_account, "unknown"),
                next_wait,
                (
                    datetime.datetime.now() + datetime.timedelta(seconds=next_wait)
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
                # Build upload data, optionally excluding accuracy
                upload_data = dict(location)
                if not REPORT_ACCURACY:
                    upload_data.pop("accuracy", None)

                # Add full identifier as attribute if available
                device_id = location["id"]
                if device_id in device_identifiers:
                    upload_data["findmy_id"] = device_identifiers[device_id]

                resp = requests.post(
                    TRACCAR_SERVER,
                    data=upload_data,
                )

                if resp.status_code == 200:
                    persistent_data["uploaded_locations"].append(location)
                    # Update device_last_timestamp to prevent re-uploading stale data
                    device_id_str = str(location["id"])
                    current_last = persistent_data["device_last_timestamp"].get(
                        device_id_str, 0
                    )
                    if location["timestamp"] > current_last:
                        persistent_data["device_last_timestamp"][
                            device_id_str
                        ] = location["timestamp"]
                elif 400 <= resp.status_code < 500:
                    # Client error - device likely doesn't exist in Traccar
                    device_id = location["id"]
                    device_name = device_names.get(device_id, f"FindMy Device {device_id}")

                    if create_traccar_device(device_id, device_name):
                        # Retry the upload after creating the device
                        retry_resp = requests.post(TRACCAR_SERVER, data=upload_data)
                        if retry_resp.status_code == 200:
                            persistent_data["uploaded_locations"].append(location)
                            # Update device_last_timestamp to prevent re-uploading stale data
                            device_id_str = str(location["id"])
                            current_last = persistent_data["device_last_timestamp"].get(
                                device_id_str, 0
                            )
                            if location["timestamp"] > current_last:
                                persistent_data["device_last_timestamp"][
                                    device_id_str
                                ] = location["timestamp"]
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
                loc
                for loc in persistent_data["uploaded_locations"]
                if loc["timestamp"] > cutoff
            ]

            last_traccar_push_timestamp = datetime.datetime.now().timestamp()

            commit(persistent_data)


def init() -> None:
    """
    One-time interactive login procedure to answer 2fa challenge and generate API token.

    Callable via the binary `.venv/bin/findmy-traccar-bridge-init`

    Usage: findmy-traccar-bridge-init [account_id]
    If account_id is not provided, defaults to 0.
    """
    # Parse account ID from command line args
    account_id = 0
    if len(sys.argv) > 1:
        try:
            account_id = int(sys.argv[1])
        except ValueError:
            print(f"Invalid account ID: {sys.argv[1]}")
            print("Usage: findmy-traccar-bridge-init [account_id]")
            sys.exit(1)

    print(f"Initializing account {account_id}...")

    acc_store = get_account_store(account_id)

    if acc_store.is_file():
        response = input(f"Account {account_id} already exists. Overwrite? [y/N] > ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    acc = create_account(account_id)

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

    # Test the account by making a simple API call
    print("Verifying account can access FindMy service...")
    try:
        # Fetch with empty device list to verify API access works
        acc.fetch_last_reports([])
        print("Account verified successfully!")
    except Exception as e:
        print(f"WARNING: Account login succeeded but verification failed: {e}")
        print("The account may still work - saving anyway.")

    # Use new persistence API
    acc.to_json(acc_store)
    print(f"Account {account_id} initialized successfully!")
    print(f"Saved to: {acc_store}")
    print()
    print("NOTE: Restart the bridge for this account to take effect.")
