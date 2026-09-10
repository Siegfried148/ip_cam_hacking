# Test captures

This directory holds real traffic captures from two Seedary-brand cameras, used to test
`rtsp_path_locator.py` against actual hardware and to document possible limitations of the
baseline-diffing approach.

## Devices

| | Camera A (`192.168.1.177`) | Camera B (`192.168.1.180`) |
| --- | --- | --- |
| PID | `XM530_RA50X20_8M` | `A9A022350235C006` |
| Firmware | `V5.00.R02.00030665.10010.343706.0000000` | `V5.03.R02000A0802.10010.342024.0000010` |
| RTSP `Server` banner | `H264DVR 1.0` | `H264DVR 1.0` |
| Result | Valid streams detected | Valid streams **not** detected |

Both were probed unauthenticated (no credentials supplied) with the same candidate list,
[`test_paths.txt`](test_paths.txt), which includes two paths known to be valid and reachable on
both cameras:

```
/user=[USERNAME]_password=[PASSWORD]_channel=0_stream=0.sdp?real_stream
/user=[USERNAME]_password=[PASSWORD]_channel=0_stream=0&onvif=0.sdp?real_stream
```

The raw pcaps are [`successful_enumeration.pcap`](successful_enumeration.pcap) (Camera A) and
[`unsuccessful_enumeration.pcap`](unsuccessful_enumeration.pcap) (Camera B).

## Camera A: valid paths are distinguishable

For every nonexistent path (including the 5 random baseline probes), Camera A replies
`401 Unauthorized` with a `WWW-Authenticate: Digest` challenge:

```
RTSP/1.0 401 Unauthorized
CSeq: 1
Server: H264DVR 1.0
WWW-Authenticate: Digest realm="4453c7aab6dbf00c",nonce="x44Brw345XKaKJy2UkUk4RP2sjVpSfMp"
```

But for the two paths that are actually valid, it replies with a *different*, much shorter
response instead (`451 ERROR`), with no `WWW-Authenticate` header at all:

```
RTSP/1.0 451 ERROR
CSeq: 1
Server: H264DVR 1.0
```

Because this camera's `DESCRIBE` handler checks whether the path exists *before* it checks
authentication, and answers each case differently, the baseline-diff approach works exactly as
designed: the script learns `401` as the baseline and flags the two `451` responses as `[+]`.

```
$ python rtsp_path_locator.py -H 192.168.1.177 -r test_paths.txt
Baseline check: probing 5 random nonexistent paths...
  401 /rtsp-path-locator-403558039283714f
  401 /rtsp-path-locator-dd6fdbf05385f5f0
  401 /rtsp-path-locator-2d0e60538097027c
  401 /rtsp-path-locator-c45666b4398e9958
  401 /rtsp-path-locator-70c2a747e9e0cc43
Baseline status code for nonexistent paths: 401

[+] 451 /user=[USERNAME]_password=[PASSWORD]_channel=0_stream=0.sdp?real_stream
[+] 451 /user=[USERNAME]_password=[PASSWORD]_channel=0_stream=0&onvif=0.sdp?real_stream

Tested: 16
Valid/probable: 2
Invalid: 14
Errors: 0
```

## Camera B: valid paths are indistinguishable from invalid ones

Camera B is confirmed to serve those same two paths (they are valid too), but the scan reports
zero hits:

```
$ python rtsp_path_locator.py -H 192.168.1.180 -r test_paths.txt
Baseline check: probing 5 random nonexistent paths...
  401 /rtsp-path-locator-939dd97c5fe571b3
  401 /rtsp-path-locator-f9336dc680f60729
  401 /rtsp-path-locator-be3a93b6bed7c1fb
  401 /rtsp-path-locator-c5aef5f4ac9effe5
  401 /rtsp-path-locator-c1dd256281cedeb2
Baseline status code for nonexistent paths: 401


Tested: 16
Valid/probable: 0
Invalid: 16
Errors: 0
```

Unlike Camera A, this firmware enforces authentication *before* it looks
at the path at all. Every single `DESCRIBE`, whether for a random nonexistent path or for one of
the two genuinely valid ones, gets the exact same `401 Unauthorized` challenge:

```
RTSP/1.0 401 Unauthorized
CSeq: 1
Server: H264DVR 1.0
WWW-Authenticate: Digest realm="2fa6c9a0b9abe5c0",nonce="..."
```

There is no observable difference at all between a valid and an invalid path in an unauthenticated
`DESCRIBE` exchange: same status code, same headers, same response size. Since the baseline-diff
technique relies on the server leaking *some* signal for valid paths before authentication, there's nothing much to do with this enumeration technique.


