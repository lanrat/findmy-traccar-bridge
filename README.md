# findmy-traccar-bridge



A simple script to continuously import [OpenHaystack](https://github.com/seemoo-lab/openhaystack) locations into [Traccar](https://www.traccar.org/).
This project uses the excellent [findmy.py](https://github.com/malmeloo/FindMy.py) project to load the encrypted location data
of your custom tracking beacons from Apple's FindMy network.

![image](https://github.com/user-attachments/assets/6f6b73d3-7cf5-4062-ad7a-13c3fbde2d6b)
![usage_screencast](https://github.com/user-attachments/assets/aa041c66-8490-470f-9abc-8da229c421d4)

## Requirements

- Docker or Python 3.12
- Some OpenHaystack beacons generating data, [decrypted plist files](https://github.com/malmeloo/FindMy.py/issues/31) for real AirTags, or JSON key files
  - e.g. an [esp32](https://github.com/dchristl/macless-haystack/blob/main/firmware/ESP32/README.md) or [NRF51](https://github.com/dchristl/macless-haystack/blob/main/firmware/nrf5x/README.md)
  - I recommend following the instructions `2. Hardware setup` from [macless-haystack](https://github.com/dchristl/macless-haystack?tab=readme-ov-file#setup). This is also where you will generate the private key for later.
- Access to an Apple account with 2FA enabled
> [!IMPORTANT]
> Using Apple's internal API like this may get your account banned, depending on how "trustworthy" Apple deems your account.
> In general, one query every 30 minutes seems to be safe, even for new throwaway accounts (this project querys once per hour by default).
> Some anecdotes from others:
> [[1]](https://github.com/dchristl/macless-haystack/pull/30#issuecomment-1858816159)
> [[2]](https://news.ycombinator.com/item?id=42480693)
> [[3]](https://news.ycombinator.com/item?id=42482047)

## Usage
Run the bridge via `docker compose`:
```yml
services:
  bridge:
    build: https://github.com/jannisko/findmy-traccar-bridge.git
    volumes:
      - ./:/bridge/data
      # Optional: Mount a directory with plist files for AirTags
      - /path/to/your/plists:/bridge/plists
      # Optional: Mount a directory with JSON key files for AirTags
      - /path/to/your/json_keys:/bridge/json_keys
    environment:
      # For OpenHaystack beacons, specify their private keys
      BRIDGE_PRIVATE_KEYS: "<key1>,<key2>,..."
      BRIDGE_TRACCAR_SERVER: "<your traccar base url>:5055"
      # Optional: Use a remote anisette server instead of built-in
      # BRIDGE_ANISETTE_SERVER: "http://anisette:6969"
```

> [!NOTE]
> The bridge now uses a **built-in anisette provider** by default, so an external anisette server is no longer required.
> If you prefer to use a remote anisette server, you can still set `BRIDGE_ANISETTE_SERVER`.

<details>
  <summary>With external anisette server (optional)</summary>

  ```yml
  services:
    bridge:
      build: https://github.com/jannisko/findmy-traccar-bridge.git
      volumes:
        - ./:/bridge/data
        - /path/to/your/plists:/bridge/plists
        - /path/to/your/json_keys:/bridge/json_keys
      environment:
        BRIDGE_PRIVATE_KEYS: "<key1>,<key2>,..."
        BRIDGE_TRACCAR_SERVER: "<your traccar base url>:5055"
        BRIDGE_ANISETTE_SERVER: "http://anisette:6969"
    anisette:
      image: dadoum/anisette-v3-server
      volumes:
        - anisette_data:/home/Alcoholic/.config/anisette-v3/lib/
  volumes:
    anisette_data:
  ```
</details>

<details>
  <summary>via docker</summary>

  ```shell
  docker build -t findmy-traccar-bridge https://github.com/jannisko/findmy-traccar-bridge.git
  docker run -d --name bridge \
  -v ./:/data \
  # Optional: Mount directory with plist files for AirTags
  -v /path/to/your/plists:/bridge/plists \
  # Optional: Mount directory with JSON key files for AirTags
  -v /path/to/your/json_keys:/bridge/json_keys \
  -e BRIDGE_PRIVATE_KEYS="<key1>,<key2>,..." \
  -e BRIDGE_TRACCAR_SERVER="<your traccar base url>" \
  findmy-traccar-bridge
  ```
</details>

<details>
  <summary>as a python package</summary>

  ```shell
  # Set up environment variables
  export BRIDGE_PRIVATE_KEYS="<key1>,<key2>,..." BRIDGE_TRACCAR_SERVER="<your traccar base url>"
  # If you want to use AirTags through plist files, they'll be detected automatically in /bridge/plists
  # Optionally you can override the plist directory:
  # export BRIDGE_PLIST_DIR="/path/to/your/plists"
  # For JSON key files:
  # export BRIDGE_JSON_DIR="/path/to/your/json_keys"

  # Run the bridge
  uvx --from=git+https://github.com/jannisko/findmy-traccar-bridge findmy-traccar-bridge
  ```
</details>

## Initialization

To query the internal Apple FindMy API you will need to interactively log into your Apple account with a 2FA challenge
when initially setting up the containers. Until this is done, the bridge container will stay idle.

```shell
docker compose exec bridge .venv/bin/findmy-traccar-bridge-init
```

<details>
  <summary>via docker</summary>

  ```shell
  docker exec -it bridge .venv/bin/findmy-traccar-bridge-init
  ```
</details>
<details>
  <summary>as a python package</summary>

  ```shell
  uvx --from=git+https://github.com/jannisko/findmy-traccar-bridge findmy-traccar-bridge-init
  ```
</details>

## Configuration

The script can be configured via the following environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BRIDGE_TRACCAR_SERVER` | Yes | - | URL to your Traccar server OsmAnd endpoint (e.g., `http://traccar:5055`) |
| `BRIDGE_PRIVATE_KEYS` | No | - | Comma-separated base64 encoded private keys for OpenHaystack beacons |
| `BRIDGE_PLIST_DIR` | No | `/bridge/plists` | Directory path for [decrypted plist files](https://github.com/malmeloo/FindMy.py/issues/31) |
| `BRIDGE_JSON_DIR` | No | `/bridge/json_keys` | Directory path for JSON key files (see [FindMy.py examples](https://github.com/malmeloo/FindMy.py/tree/main/examples)) |
| `BRIDGE_ANISETTE_SERVER` | No | *(built-in)* | URL to a remote anisette server. If not set, uses the built-in local anisette provider (recommended) |
| `BRIDGE_POLL_INTERVAL` | No | `3600` | Seconds between Apple API queries. Too frequent polling may get your account banned |
| `BRIDGE_LOGGING_LEVEL` | No | `INFO` | Logging verbosity level |
| `BRIDGE_AUTO_CREATE_DEVICES` | No | `false` | Set to `true` to automatically create devices in Traccar when first seen |
| `BRIDGE_TRACCAR_API` | No | - | Traccar REST API URL (e.g., `http://traccar:8082`). Required for auto-create |
| `BRIDGE_TRACCAR_USER` | No | - | Traccar admin username for API authentication. Required for auto-create |
| `BRIDGE_TRACCAR_PASS` | No | - | Traccar admin password for API authentication. Required for auto-create |

### Device Configuration

You need at least one of the following configured:
1. **OpenHaystack beacons**: Set `BRIDGE_PRIVATE_KEYS` with comma-separated base64 keys
2. **AirTags via plist**: Mount `.plist` files to `/bridge/plists` (or set `BRIDGE_PLIST_DIR`)
3. **AirTags via JSON**: Mount `.json` key files to `/bridge/json_keys` (or set `BRIDGE_JSON_DIR`)

### Battery Level

The bridge reports battery level to Traccar as the `batt` attribute (percentage: 100=Full, 75=Medium, 50=Low, 25=Very Low).

### Auto-Create Devices

By default, devices must be manually created in Traccar before location updates will be accepted. You can enable automatic device creation by setting the following environment variables:

```yaml
environment:
  BRIDGE_AUTO_CREATE_DEVICES: "true"
  BRIDGE_TRACCAR_API: "http://traccar:8082"
  BRIDGE_TRACCAR_USER: "admin@example.com"
  BRIDGE_TRACCAR_PASS: "your-password"
```

When enabled, the bridge will automatically create devices in Traccar when it first tries to upload a location. Devices will be named based on their AirTag name/identifier or "Haystack" prefix for OpenHaystack beacons.

> [!NOTE]
> Auto-create uses the Traccar REST API (port 8082) which requires authentication, while location updates use the OsmAnd protocol (port 5055) which does not require authentication.

> [!TIP]
> Self-hosting Anisette (and setting `BRIDGE_ANISETTE_SERVER`) is optional. The built-in anisette provider is now the default and recommended approach. If you experience authentication issues, you can try using a self-hosted anisette server instead.

## Example

An example compose file running the bridge and Traccar locally can be found in the [testing](./testing) directory:
```shell
git clone https://github.com/jannisko/findmy-traccar-bridge
cd findmy-traccar-bridge/testing
docker compose up -d
docker compose exec bridge .venv/bin/findmy-traccar-bridge-init
```
