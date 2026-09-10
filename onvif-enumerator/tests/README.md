# Analyzing `onvif-enumerator.py` results with `jq`

`onvif-enumerator.py` dumps a very complete but very large JSON per device (thousands of lines: codec configs, service capabilities, event topics, PTZ, imaging...).

`jq` lets you pull out just what matters, compare devices quickly, and feed results straight into other tools (e.g. RTSP URIs into `ffprobe`, usernames into a wordlist, etc).

Below: one query per use case using the files `results_1.json` and `results2_json`.

---

## 1. Device fingerprint

Identifies vendor/model/firmware for known-CVE or default-credential lookups.

**Command**
```bash
jq -r '
  "ONVIF URL:    \(.target.onvif_url)",
  "Manufacturer: \(.device.Manufacturer)",
  "Model:        \(.device.Model)",
  "Firmware:     \(.device.FirmwareVersion)",
  "Serial:       \(.device.SerialNumber)"
' <file>
```

**Output — `results_1.json`**
```
ONVIF URL:    http://192.168.1.177:8899/onvif/device_service
Manufacturer: H264
Model:        XM530_RA50X20_8M
Firmware:     V5.00.R02.00030665.10010.343706..ONVIF 16.12
Serial:       efbd1abef49879fc
```

**Output — `results_2.json`**
```
ONVIF URL:    http://192.168.1.150:80/onvif/device_service
Manufacturer: Hangzhou Hikvision Digital Technology Co., Ltd
Model:        DVR-104G-K1
Firmware:     V4.71.410, build 230918
Serial:       0420231204CCWRAX5245576WCVU
```

---

## 2. Users and roles

Maps the credential attack surface: default/extra accounts, privilege levels.

**Command**
```bash
jq -r '
  .users[] |
  "Username:   \(.Username)",
  "User Level: \(.UserLevel)"
' <file>
```

**Output — `results_1.json`**
```
Username:   admin
User Level: Administrator
```

**Output — `results_2.json`**
```
Username:   admin
User Level: Administrator
Username:   guest
User Level: Operator
```

---

## 3. Valid RTSP stream URIs

Combines `media.stream_uris` (ONVIF ver10) and `media2.stream_uris` (ver20), deduped.

**Command**
```bash
jq -r '[.media.stream_uris, .media2.stream_uris]
       | map(select(. != null) | to_entries[].value)
       | .[]' <file> | sort -u
```

**Output — `results_1.json`**
```
rtsp://192.168.1.177:554/stream=2
rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=0.sdp?real_stream
rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=1.sdp?real_stream
```

**Output — `results_2.json`**
```
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/101
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/102
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/201
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/202
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/301
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/302
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/401
rtsp://192.168.1.150:10554/Streaming/Unicast/channels/402
```

---

## 4. Authentication posture

Whether ONVIF enforces auth, whether creds were supplied, and TLS status.

**Command**
```bash
jq '{onvif_url: .target.onvif_url, auth: .authentication}' <file>
```

**Output — `results_1.json`**
```json
{
  "onvif_url": "http://192.168.1.177:8899/onvif/device_service",
  "auth": {
    "http_auth": false,
    "ws_security": false,
    "tls_verified": true,
    "credentials_provided": false,
    "required": false,
    "status": "ok"
  }
}
```

**Output — `results_2.json`**
```json
{
  "onvif_url": "http://192.168.1.150:80/onvif/device_service",
  "auth": {
    "http_auth": true,
    "ws_security": false,
    "tls_verified": true,
    "credentials_provided": true,
    "required": true,
    "status": "ok"
  }
}
```

---

## 5. Oneshot recon summary

Combines everything above into one object per device.

**Command**
```bash
jq '{
  target: .target.onvif_url,
  device: {mfr: .device.Manufacturer, model: .device.Model, fw: .device.FirmwareVersion, sn: .device.SerialNumber},
  auth_required: .authentication.required,
  users: [.users[] | .Username+":"+.UserLevel],
  rtsp: ([.media.stream_uris, .media2.stream_uris] | map(select(.!=null)|to_entries[].value) | unique)
}' <file>
```

**Output — `results_1.json`**
```json
{
  "target": "http://192.168.1.177:8899/onvif/device_service",
  "device": {
    "mfr": "H264",
    "model": "XM530_RA50X20_8M",
    "fw": "V5.00.R02.00030665.10010.343706..ONVIF 16.12",
    "sn": "efbd1abef49879fc"
  },
  "auth_required": false,
  "users": [
    "admin:Administrator"
  ],
  "rtsp": [
    "rtsp://192.168.1.177:554/stream=2",
    "rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=0.sdp?real_stream",
    "rtsp://192.168.1.177:554/user=admin_password=NE83HO2r_channel=0_stream=1.sdp?real_stream"
  ]
}
```

**Output — `results_2.json`**
```json
{
  "target": "http://192.168.1.150:80/onvif/device_service",
  "device": {
    "mfr": "Hangzhou Hikvision Digital Technology Co., Ltd",
    "model": "DVR-104G-K1",
    "fw": "V4.71.410, build 230918",
    "sn": "0420231204CCWRAX5245576WCVU"
  },
  "auth_required": true,
  "users": [
    "admin:Administrator",
    "guest:Operator"
  ],
  "rtsp": [
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/101",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/102",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/201",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/202",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/301",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/302",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/401",
    "rtsp://192.168.1.150:10554/Streaming/Unicast/channels/402"
  ]
}
```

