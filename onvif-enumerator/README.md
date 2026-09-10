# ONVIF Enumerator

Enumerates an ONVIF-compliant IP camera/NVR/DVR over SOAP, or finds ONVIF devices on
the local network via WS-Discovery. Given a Device Service URL, it walks every
standard ONVIF service the device advertises:
- Device
- Media
- Media2
- PTZ
- Imaging
- Events
- Analytics
- DeviceIO
- Recording
- Search
- Replay

The program dumps dumps everything it
learns (e.g. device info, users, network config, media profiles, stream/snapshot URIs,
service capabilities, event topics, etc.) into a single consolidated JSON file.

Authentication is handled automatically: the tool probes the Device Service first to
find out whether auth is required and which mechanism it expects (HTTP Basic/Digest or
WS-Security UsernameToken), then uses the right one for every subsequent call.

## Requirements

Python 3.8+, plus:

- `requests>=2.28`
- `defusedxml>=0.7`

```bash
pip install -r requirements.txt
```


## Usage

Find ONVIF devices on the LAN via WS-Discovery:

```bash
python3 onvif-enumerator.py --discovery
```

Enumerate a device that doesn't require authentication (the URL can be extracted from the discovery module):

```bash
python3 onvif-enumerator.py --onvif-url <url>
```

Enumerate a device with credentials:

```bash
python3 onvif-enumerator.py --onvif-url <url> --username <username> --password <password>
```

Save the JSON to a file and show progress:

```bash
python3 onvif-enumerator.py -u <url> -U <username> -P <password> -o <file> -v
```

## Options

| Flag | Short | Default | Meaning |
| --- | --- | --- | --- |
| `--discovery` | `-d` | off | WS-Discovery only: find ONVIF devices on the LAN. Mutually exclusive with `--onvif-url`. |
| `--onvif-url` | `-u` | *(required unless `-d`)* | ONVIF Device Service URL to enumerate |
| `--username` | `-U` | none | ONVIF username (requires `--password`) |
| `--password` | `-P` | none | ONVIF password (requires `--username`) |
| `--output` | `-o` | none | Also write the JSON result to this file |
| `--verbose` | `-v` | off | Print progress to stderr |


## Output

Everything is printed as a single JSON document to stdout (and to `--output` if given).

**`--discovery` output** is a list of devices found via WS-Discovery, each with the
raw ProbeMatch fields:

```json
{
  "discovery": {
    "devices": [
      {
        "endpoint_reference": "urn:uuid:...",
        "source_ip": "192.168.1.177",
        "xaddrs": ["http://192.168.1.177:8899/onvif/device_service"],
        "types": ["dn:NetworkVideoTransmitter"],
        "scopes": ["onvif://www.onvif.org/type/video_encoder", "..."]
      }
    ]
  }
}
```

**`--onvif-url` output** is one JSON object per device with a fixed set of top-level
keys, populated based on which services the device actually advertises:

| Key | Contents |
| --- | --- |
| `target` | The URL that was enumerated |
| `authentication` | Whether auth is required, which mechanism, and whether it succeeded |
| `device` | Manufacturer, model, firmware, serial, conformance profiles (Profile S/T/G/...) |
| `scopes` | Raw ONVIF scope URIs advertised by the device |
| `network` | Hostname, DNS, NTP, interfaces, protocols/ports, gateway |
| `users` | Configured accounts and privilege levels |
| `services` | Every ONVIF service the device exposes: namespace, endpoint URL, version, capabilities |
| `media` / `media2` | Profiles, encoder/source configs, stream URIs, snapshot URIs (ver10/ver20) |
| `imaging`, `ptz`, `events`, `analytics`, `device_io`, `recording`, `search`, `replay` | Per-service settings and capabilities, present only if the device supports that service |
| `extensions` | Vendor-specific XML elements encountered, kept by namespace for fingerprinting |
| `errors` | Every SOAP fault/HTTP error hit along the way, with operation and service |

This is intentionally exhaustive, so only
the shape is shown here. This is a reduced example, of interest fields:

```json
{
  "target": {"onvif_url": "http://192.168.1.177:8899/onvif/device_service"},
  "authentication": {"required": false, "credentials_provided": false, "status": "ok"},
  "device": {"Manufacturer": "H264", "Model": "XM530_RA50X20_8M", "FirmwareVersion": "V5.00...ONVIF 16.12"},
  "users": [{"Username": "admin", "UserLevel": "Administrator"}],
  "media": {"stream_uris": {"PROFILE_000": "rtsp://192.168.1.177:554/..."}}
}
```

## Tests

The `tests/` directory has full, real-world example outputs from two different
devices:
- `results_1.json` (a generic H264/XM530 IP camera)
- `results_2.json` (a Hikvision `DVR-104G-K1`) 

There you'll find ready-to-use `jq` recipes for
pulling the security-relevant fields (e.g. device fingerprint, users/roles, RTSP URIs) out of the full JSON.

