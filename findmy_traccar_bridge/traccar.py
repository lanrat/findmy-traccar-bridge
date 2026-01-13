"""Traccar integration for findmy-traccar-bridge.

Handles device creation via the Traccar REST API.
"""

import os
from typing import TypedDict

import requests
from loguru import logger


# Traccar configuration from environment
AUTO_CREATE_DEVICES = os.environ.get("BRIDGE_AUTO_CREATE_DEVICES", "").lower() in (
    "true",
    "1",
    "yes",
)
TRACCAR_API_URL = os.environ.get("BRIDGE_TRACCAR_API", "")  # e.g., http://traccar:8082
TRACCAR_API_USER = os.environ.get("BRIDGE_TRACCAR_USER", "")
TRACCAR_API_PASS = os.environ.get("BRIDGE_TRACCAR_PASS", "")


class Location(TypedDict):
    """Location data to be sent to Traccar."""

    id: int
    timestamp: int
    lat: float
    lon: float
    batt: int  # Battery percentage (0-100)
    accuracy: int  # Horizontal accuracy in meters


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
