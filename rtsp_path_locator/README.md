# RTSP Path Locator

Probes an RTSP server with a list of candidate paths (e.g. `/cam/realmonitor?channel=1&subtype=0`,
`/Streaming/Channels/101`) and reports which ones look valid, by sending an RTSP `DESCRIBE`
request for each and comparing the response against a calibrated baseline.

Before testing the candidate paths, the script first
probes a handful of random, guaranteed-nonexistent paths to learn what "not found" looks like on
that specific RTSP server, then flags any path whose response differs from that baseline as a
potential hit.

## Requirements

Python 3.10+. No third-party packages, standard library only.

## Usage

Probe a host with a list of candidate paths:

```bash
python3 rtsp_probe.py --host 192.168.1.50 --routes paths.txt
# short form:
python3 rtsp_probe.py -H 192.168.1.50 -r paths.txt
```

Non-standard port, and save results to a file:

```bash
python3 rtsp_probe.py --host 192.168.1.50 --port 8554 --routes paths.txt --output results.txt
# short form:
python3 rtsp_probe.py -H 192.168.1.50 -p 8554 -r paths.txt -o results.txt
```

Slow down requests and show rejected paths too:

```bash
python3 rtsp_probe.py --host 192.168.1.50 --routes paths.txt --delay 0.5 --verbose
# short form:
python3 rtsp_probe.py -H 192.168.1.50 -r paths.txt -d 0.5 -v
```

`--routes` expects a text file with one path per line (leading `/`), e.g.:

```
/cam/realmonitor?channel=1&subtype=0
/Streaming/Channels/101
/live.sdp
```

Blank lines and lines starting with `#` are ignored.

## Options

| Flag | Short | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `-H` | *(required)* | Target IP address or hostname |
| `--routes` | `-r` | *(required)* | File with candidate RTSP paths, one per line |
| `--port` | `-p` | `554` | RTSP port |
| `--delay` | `-d` | `0` | Delay in seconds between requests |
| `--timeout` | `-t` | `3` | Per-request socket timeout (seconds) |
| `--verbose` | `-v` | off | Also show invalid/rejected paths |
| `--output` | `-o` | none | Write results to this file, in addition to stdout |

## Output

For each candidate path, a line is printed with a marker:

- **`[+]`**: response differs from the baseline; likely a valid path.
- **`[-]`**: response matches the baseline (looks invalid); only shown with `--verbose`.
- **`[!]`**: network error, timeout, or unparseable response; the reason is shown instead of a
  status code.

Example:

```
[+] 200 /cam/realmonitor?channel=1&subtype=0
[!] timeout /Streaming/Channels/201
```

## Executed tests

The tool may have false negatives, as the RTSP path may be in the dictionary and still it is not marked as a valid result. This can happen for many reasons, but is mainly dependent on how each camera handles unauthenticated DESCRIBE messages.

For more details on some tests I executed, see the `tests` directory. 
