"""Device loading and battery helpers for findmy-traccar-bridge.

Handles loading AirTags from plist and JSON files, and battery level extraction.
"""

from pathlib import Path

from findmy import FindMyAccessory
from loguru import logger


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


def load_airtags_from_json_directory(
    directory_path: str | None,
) -> tuple[list[FindMyAccessory], dict[FindMyAccessory, Path]]:
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
