#!/usr/bin/env python3
"""Crawl iSpyConnect's camera database and extract every unique RTSP path
template it publishes.

Usage:
    python3 extract_rtsp_paths.py [--output-dir DIR] [--workers N] [--limit N]
"""

import argparse
import concurrent.futures
import html
import json
import os
import re
import string
import sys
import time
import requests
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup

BASE_URL = "https://www.ispyconnect.com"
CAMERAS_URL = f"{BASE_URL}/cameras"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) RTSPPathExtractor/1.0 "
)

# Everything worth crawling lives under /camera or /cameras
CRAWLABLE_PATH_RE = re.compile(r"^/camera(s)?(/|$|\?)")

# Captures the path+query of any rtsp:// reference in a response body
RTSP_TEXT_RE = re.compile(r"rtsp://[^\s\"'<>]*?(/[^\s\"'<>]*)", re.IGNORECASE)

# Best-effort discovery of AJAX/API endpoints referenced from inline
# scripts, in case model data is ever loaded dynamically on some page.
API_ENDPOINT_RE = re.compile(
    r"""(?:fetch|\.ajax|axios(?:\.get|\.post)?)\s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def fetch(session, url, retries=3, timeout=20):
    """GET a URL, retrying on transient failures (timeouts, 429/5xx).
    Args:
        session: requests.Session to issue the GET through.
        url: URL to fetch.
        retries: max attempts before giving up.
        timeout: per-attempt timeout in seconds.
    Returns:
        Response body as str, or None if every attempt failed or the
        server returned a non-retryable error (e.g. 404).
    """
    for attempt in range(retries):
        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException:
            time.sleep(1.5 ** attempt)
            continue
        if resp.status_code == 200:
            return resp.text
        if resp.status_code in (429, 500, 502, 503, 504):
            time.sleep(1.5 ** attempt)
            continue
        return None  # 404 or similar - retrying won't help
    return None


def normalize_path(raw):
    """Decode and trim a raw path into a canonical template string.
    Args:
        raw: raw path string pulled from a `data-path` attribute or
            RTSP_TEXT_RE match, or None.
    Returns:
        Cleaned path as str, or None if nothing usable remains.
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    s = html.unescape(s)
    s = s.strip("'\"")
    s = s.replace("\\/", "/")
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = s.strip()
    return s or None


def extract_from_table(page_html, page_url):
    """Extract RTSP entries from a manufacturer page's connection table.
    Args:
        page_html: raw HTML of a manufacturer page.
        page_url: URL it was fetched from, stored per entry.
    Returns:
        Tuple of (entries, soup): entries is a list of (path, port, conn,
        page_url) tuples, one per matching row; soup is the parsed
        BeautifulSoup document, returned so callers can reuse it.
    """
    entries = []
    soup = BeautifulSoup(page_html, "html.parser")
    for row in soup.find_all(attrs={"data-protocol": True}):
        protocol = (row.get("data-protocol") or "").strip().lower()
        if "rtsp" not in protocol:
            continue
        path = normalize_path(row.get("data-path"))
        if not path:
            continue
        entries.append((path, row.get("data-port"), row.get("data-conn"), page_url))
    return entries, soup


def extract_from_text(page_html, page_url):
    """Fallback: find rtsp:// mentions outside the connection table.
    Args:
        page_html: raw HTML/text of a fetched page.
        page_url: URL it was fetched from, stored per entry.
    Returns:
        List of (path, port, conn, page_url) tuples; port and conn are
        always None since free text carries no such metadata.
    """
    entries = []
    decoded = html.unescape(page_html)
    for match in RTSP_TEXT_RE.finditer(decoded):
        path = normalize_path(match.group(1))
        if path:
            entries.append((path, None, None, page_url))
    return entries


def discover_links(page_html, page_url, soup):
    """Find in-scope links and API endpoints to crawl next from a page.
    Args:
        page_html: raw HTML of the page, scanned for API_ENDPOINT_RE
            matches in inline scripts.
        page_url: URL the page was fetched from, used to resolve hrefs.
        soup: parsed BeautifulSoup document for page_html.
    Returns:
        Set of absolute URLs to crawl next.
    """
    base_host = urlparse(BASE_URL).netloc
    links = set()
    for a in soup.find_all("a", href=True):
        url = urljoin(page_url, a["href"])
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != base_host:
            continue
        if not CRAWLABLE_PATH_RE.match(parsed.path):
            continue
        if parsed.fragment:
            continue  # in-page anchors (e.g. ?model=...#wizard), not a new page
        links.add(urlunparse(parsed._replace(fragment="")))
    for m in API_ENDPOINT_RE.finditer(page_html):
        url = urljoin(page_url, m.group(1))
        if urlparse(url).netloc in ("", base_host):
            links.add(url)
    return links


def manufacturer_of(url):
    """Return the manufacturer slug for a `/camera/<name>` page.
    Args:
        url: absolute URL being (or about to be) fetched.
    Returns:
        The manufacturer slug (e.g. "axis"), or None if the URL isn't a
        manufacturer page (an index/letter-facet page or a discovered AJAX
        endpoint).
    """
    path = urlparse(url).path.rstrip("/")
    if path.startswith("/camera/"):
        return path.rsplit("/camera/", 1)[-1] or None
    return None


def crawl(seed_urls, workers, timeout, retries, limit, verbose):
    """Breadth-first crawl from seed_urls, extracting RTSP entries per page.
    Args:
        seed_urls: initial URLs to crawl.
        workers: max concurrent HTTP requests.
        timeout: per-request timeout in seconds, passed to fetch().
        retries: retry attempts per request, passed to fetch().
        limit: stop after this many pages fetched, or None for no limit.
        verbose: print the current manufacturer and pages-fetched count to
            stderr as the crawl progresses. When False, nothing is printed
            until the final summary in main().
    Returns:
        Tuple of (raw_entries, fetched, failed): raw_entries is a list of
        (path, port, conn, source_url) tuples gathered from every page
        visited; fetched is the total page count; failed is the list of
        URLs that never returned a usable response.
    """
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    visited = set()
    queue = deque(seed_urls)
    raw_entries = []  # (path, port, conn, source_url)
    fetched = 0
    failed = []
    last_manufacturer = None

    def worker(url):
        """Fetch one URL for the thread pool.
        Returns:
            Tuple of (url, body_or_None).
        """
        return url, fetch(session, url, retries=retries, timeout=timeout)

    while queue:
        wave = []
        while queue and (limit is None or fetched + len(wave) < limit):
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            wave.append(url)
        if not wave:
            break

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for url, body in pool.map(worker, wave):
                fetched += 1
                if verbose:
                    manufacturer = manufacturer_of(url)
                    if manufacturer and manufacturer != last_manufacturer:
                        print(f"  -> {manufacturer} ({fetched} pages fetched)", file=sys.stderr)
                        last_manufacturer = manufacturer
                if body is None:
                    failed.append(url)
                    continue
                table_entries, soup = extract_from_table(body, url)
                raw_entries.extend(table_entries)
                raw_entries.extend(extract_from_text(body, url))
                for link in discover_links(body, url, soup):
                    if link not in visited:
                        queue.append(link)

    return raw_entries, fetched, failed


def build_dataset(raw_entries):
    """Group raw entries into one record per unique path.
    Args:
        raw_entries: list of (path, port, conn, source_url) tuples.
    Returns:
        Dict mapping each path to a record with "ports", "conns", and
        "manufacturers" sets.
    """
    dataset = {}
    for path, port, conn, source in raw_entries:
        entry = dataset.setdefault(path, {"path": path, "ports": set(), "conns": set(), "manufacturers": set()})
        if port not in (None, ""):
            entry["ports"].add(port)
        if conn:
            entry["conns"].add(conn)
        manufacturer = urlparse(source).path.rsplit("/camera/", 1)[-1] if "/camera/" in source else None
        if manufacturer:
            entry["manufacturers"].add(manufacturer)
    return dataset


def main():
    """Parse CLI args, run the crawl, and write the output files.
    Reads command-line flags (see --help); writes rtsp_paths.txt,
    rtsp_paths.json, and failed_urls.txt (if any) into --output-dir.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output-dir", default=".", help="directory to write output files into")
    parser.add_argument("-w", "--workers", type=int, default=10, help="concurrent HTTP requests")
    parser.add_argument("-t", "--timeout", type=int, default=20, help="per-request timeout in seconds")
    parser.add_argument("-r", "--retries", type=int, default=3, help="retry attempts per request")
    parser.add_argument("-l", "--limit", type=int, default=None, help="stop after N pages fetched (for testing)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="print the current manufacturer and pages-fetched count as the crawl progresses")
    args = parser.parse_args()

    seed_urls = [CAMERAS_URL] + [f"{CAMERAS_URL}?letter={c}" for c in string.ascii_uppercase + string.digits]

    if args.verbose:
        print(f"Seeding crawl with {len(seed_urls)} index pages (root + A-Z + 0-9 letter facets)...", file=sys.stderr)
    raw_entries, fetched, failed = crawl(
        seed_urls, workers=args.workers, timeout=args.timeout, retries=args.retries,
        limit=args.limit, verbose=args.verbose,
    )

    dataset = build_dataset(raw_entries)

    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    txt_path = f"{out_dir.rstrip('/')}/rtsp_paths.txt"
    json_path = f"{out_dir.rstrip('/')}/rtsp_paths.json"

    with open(txt_path, "w", encoding="utf-8") as f:
        for path in sorted(dataset):
            f.write(path + "\n")

    json_records = [
        {
            "path": path,
            "ports": sorted(entry["ports"]),
            "connections": sorted(entry["conns"]),
            "manufacturers": sorted(entry["manufacturers"]),
        }
        for path, entry in sorted(dataset.items())
    ]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_records, f, indent=2)

    if failed:
        failed_path = f"{out_dir.rstrip('/')}/failed_urls.txt"
        with open(failed_path, "w", encoding="utf-8") as f:
            for url in failed:
                f.write(url + "\n")
        print(f"{len(failed)} pages failed after retries; see {failed_path}", file=sys.stderr)

    print(f"\nFetched {fetched} pages, {len(failed)} failed.")
    print(f"Extracted {len(dataset)} unique RTSP path templates.")
    print(f"Wrote {txt_path}")
    print(f"Wrote {json_path}")


if __name__ == "__main__":
    main()
