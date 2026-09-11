# ONVIF Enumerator (Nmap NSE)

An Nmap script that enumerates the fields most useful during recon: whether the device requires authentication (and
which mechanism), basic device identification, and the credential/RTSP attack
surface.

Given an ONVIF Device Service, the script:
1. Probes the service unauthenticated to find out whether authentication is required
   and, if so, whether it expects HTTP Basic, HTTP Digest, or WS-Security
   UsernameToken. Credentials are only tried once the mechanism is known.
2. If authentication succeeds (or wasn't required), reports:
   - **Device**: Manufacturer, Model, Firmware Version, Serial Number, Hardware Id.
   - **Users**: configured accounts and their privilege levels.
   - **RTSP URIs**: stream URIs pulled from every Media (ver10) and Media2 (ver20)
     profile the device advertises.

## Requirements

Nmap 7.x with Lua 5.4 and the `openssl` NSE binding (present in virtually every
distro build of Nmap; only needed for the WS-Security UsernameToken digest).

Install the script into Nmap's script directory, or run it straight from this
repository with `--script <path>` as shown below.

## Usage

Scan the common ONVIF ports for devices that don't require authentication:

```bash
nmap -p 80,443,2020,5000,8000,8080,8081,8443,8899 --script onvif-enumerator.nse <target>
```

Try credentials against a device that does require authentication (the auth mechanism is handled by the script):

```bash
nmap -p 8899 --script onvif-enumerator.nse \
  --script-args onvif-enumerator.username=admin,onvif-enumerator.password=admin <target>
```

Point at a non-default Device Service path:

```bash
nmap -p 8000 --script onvif-enumerator.nse \
  --script-args onvif-enumerator.path=/onvif/device_service <target>
```

## Script arguments

| Argument | Default | Meaning |
| --- | --- | --- |
| `onvif-enumerator.path` | `/onvif/device_service` | Path to the ONVIF Device Service. |
| `onvif-enumerator.username` | none | Username to try if the device requires authentication. |
| `onvif-enumerator.password` | none | Password to try (must be given together with `.username`). |

## Port selection

The script's `portrule` matches a curated list of ports actually seen on consumer/industrial IP cameras, NVRs and DVRs
(`2020, 5000, 8000, 8080, 8081, 8443, 8899`), on top of anything Nmap's own service
detection already flagged as HTTP(S). If a target's ONVIF service sits on some other
port, force it with `-p`.

## Output

If nothing SOAP-shaped answers on the probed path, the script stays silent, like
other service-detection scripts do for a non-match. Otherwise:

```
| onvif-enumerator:
|   Authentication:
|     Required: true
|     Mechanism: WS-Security (UsernameToken)
|     Credentials provided: true
|     Status: ok
|   Device:
|     Manufacturer: H264
|     Model: XM530_RA50X20_8M
|     Firmware Version: V5.00.R02.00030665.10010.343706..ONVIF 16.12
|     Serial Number: efbd1abef49879fc
|     Hardware Id: HW1
|   Users:
|
|       Username: admin
|       UserLevel: Administrator
|   RTSP URIs:
|     rtsp://192.168.1.177:554/stream=2
|_    rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=0.sdp?real_stream
```
