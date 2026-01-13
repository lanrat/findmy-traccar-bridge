"""Apple account management for findmy-traccar-bridge.

Handles account storage, discovery, migration, and loading.
"""

import os
from pathlib import Path

from findmy.reports import (
    AppleAccount,
    LocalAnisetteProvider,
    RemoteAnisetteProvider,
)
from loguru import logger


# Data storage paths
data_folder = Path("./data/")
data_folder.mkdir(exist_ok=True)
accounts_folder = data_folder / "accounts"
accounts_folder.mkdir(exist_ok=True)

# Legacy paths for backwards compatibility / migration
legacy_acc_store = data_folder / "account.json"
legacy_anisette_store = data_folder / "ani_libs.bin"


def get_account_folder(account_id: int) -> Path:
    """Get the folder path for a specific account."""
    folder = accounts_folder / str(account_id)
    folder.mkdir(exist_ok=True)
    return folder


def get_account_store(account_id: int) -> Path:
    """Get the account.json path for a specific account."""
    return get_account_folder(account_id) / "account.json"


def get_anisette_store(account_id: int) -> Path:
    """Get the anisette libs path for a specific account."""
    return get_account_folder(account_id) / "ani_libs.bin"


def migrate_legacy_account() -> None:
    """Migrate legacy single-account format to new multi-account structure."""
    if legacy_acc_store.is_file() and not get_account_store(0).is_file():
        logger.info("Migrating legacy account to multi-account structure...")
        account_0_folder = get_account_folder(0)

        # Move account.json
        legacy_acc_store.rename(account_0_folder / "account.json")
        logger.info("Migrated account.json to accounts/0/")

        # Move anisette libs if they exist
        if legacy_anisette_store.is_file():
            legacy_anisette_store.rename(account_0_folder / "ani_libs.bin")
            logger.info("Migrated ani_libs.bin to accounts/0/")


def discover_accounts() -> list[int]:
    """Discover all initialized accounts by scanning the accounts directory."""
    account_ids = []
    for item in accounts_folder.iterdir():
        if item.is_dir() and (item / "account.json").is_file():
            try:
                account_ids.append(int(item.name))
            except ValueError:
                continue
    return sorted(account_ids)


def create_account(account_id: int) -> AppleAccount:
    """
    Create an AppleAccount with appropriate anisette provider.
    Uses LocalAnisetteProvider if BRIDGE_ANISETTE_SERVER is not set (recommended).
    """
    anisette_server = os.environ.get("BRIDGE_ANISETTE_SERVER")
    anisette_store = get_anisette_store(account_id)

    if anisette_server:
        logger.info("Using remote anisette server: {}", anisette_server)
        anisette = RemoteAnisetteProvider(anisette_server)
    else:
        logger.info("Using built-in local anisette provider for account {}", account_id)
        anisette = LocalAnisetteProvider(libs_path=str(anisette_store))

    return AppleAccount(anisette)


def load_account(account_id: int) -> AppleAccount:
    """Load account from JSON store."""
    import json

    anisette_server = os.environ.get("BRIDGE_ANISETTE_SERVER")
    anisette_store = get_anisette_store(account_id)
    acc_store = get_account_store(account_id)

    libs_path = None if anisette_server else str(anisette_store)
    try:
        return AppleAccount.from_json(acc_store, anisette_libs_path=libs_path)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        logger.error("Failed to load account {} (may be old format): {}", account_id, e)
        logger.error(
            "Please delete {} and re-run findmy-traccar-bridge-init {}", acc_store, account_id
        )
        raise
