# iSpyConnect RTSP Path Extractor

Crawls [iSpyConnect's camera database](https://www.ispyconnect.com/cameras) and
extracts every unique RTSP path template it publishes (e.g.
`/cam/realmonitor?channel=1&subtype=0`, `/Streaming/Channels/101`).

## Requirements

```bash
pip install requests beautifulsoup4
```

## Usage

Run a full crawl (writes to the current directory by default):

```bash
python3 extract_rtsp_paths.py
```

Write output elsewhere, with more concurrency:

```bash
python3 extract_rtsp_paths.py --output-dir ./out --workers 20
```

Quick smoke test (stop after 40 pages):

```bash
python3 extract_rtsp_paths.py --limit 40
```

All options (each has a short form):

| Flag | Short | Default | Meaning |
| --- | --- | --- | --- |
| `--output-dir` | `-o` | `.` | Directory to write output files into |
| `--workers` | `-w` | `10` | Concurrent HTTP requests |
| `--timeout` | `-t` | `20` | Per-request timeout (seconds) |
| `--retries` | `-r` | `3` | Retry attempts per request |
| `--limit` | `-l` | none | Stop after N pages fetched (testing) |
| `--verbose` | `-v` | off | Print progress (current manufacturer + pages fetched) as the crawl runs |

## Progress output

By default the crawler prints nothing more than the final summary:

```
Fetched 1842 pages, 0 failed.
Extracted 613 unique RTSP path templates.
Wrote ./rtsp_paths.txt
Wrote ./rtsp_paths.json
```

Pass `--verbose`/`-v` to see the status:


```
  -> geovision (41 pages fetched so far)
  -> gwsecurity (45 pages fetched so far)
  -> hikvision (52 pages fetched so far)
```

## Output

- **`rtsp_paths.txt`**: sorted, deduplicated list of RTSP path templates, one per line.
- **`rtsp_paths.json`**: same paths with metadata: ports, connection types, and manufacturers observed for each.
- **`failed_urls.txt`**: only written if some pages failed after retries.
