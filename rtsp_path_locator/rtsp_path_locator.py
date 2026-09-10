#!/usr/bin/env python3
"""Probe an RTSP server with a list of candidate paths and report which ones look valid."""

import argparse
import secrets
import socket
import sys
import time

# Different servers use different codes to mean "this path doesn't exist".
# Thus, we first calibrate: probe this many random, guaranteed-nonexistent paths first and
# learn what the server actually returns for garbage, then flag anything that differs.
BASELINE_PROBE_COUNT = 5


def read_routes(path):
    """Read candidate RTSP paths from a file.
    Args:
        path: Path to a text file with one candidate route per line.
    Returns:
        The list of routes found, in file order, with blank lines and lines
        starting with "#" excluded.
    """
    routes = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            routes.append(line)
    return routes


def probe_route(host, port, route, timeout):
    """Send an RTSP DESCRIBE request for one route and read the server's reply.
    Args:
        host: Target IP address or hostname.
        port: RTSP port to connect to.
        route: Candidate path to append to the RTSP URL, e.g. "/live.sdp".
        timeout: Socket connect/receive timeout, in seconds.
    Returns:
        A (status_code, status_text) tuple. status_code is the integer RTSP
        status code on a successful exchange, or None on network errors,
        timeouts, or an unparseable response; status_text is the response's
        reason phrase, or a short description of what went wrong when
        status_code is None.
    """
    url = f"rtsp://{host}:{port}{route}"
    request = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"Accept: application/sdp\r\n"
        f"User-Agent: rtsp-path-locator/1.0\r\n"
        f"\r\n"
    )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request.encode())
            sock.settimeout(timeout)
            response = sock.recv(4096).decode(errors="replace")
    except socket.timeout:
        return None, "timeout"
    except ConnectionRefusedError:
        return None, "connection refused"
    except OSError as e:
        return None, f"error: {e}"

    status_line = response.split("\r\n", 1)[0]
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None, "unparseable response"

    code = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    return code, reason


def establish_baseline(host, port, timeout):
    """Probe random nonexistent paths to learn the server's status code for a bad path.
    Args:
        host: Target IP address or hostname.
        port: RTSP port to connect to.
        timeout: Socket connect/receive timeout, in seconds, for each probe.
    Returns:
        The most common status code seen across the baseline probes, or None
        if the server didn't answer consistently (or at all), in which case
        every successful response is later treated as interesting.
    """
    print(f"Baseline check: probing {BASELINE_PROBE_COUNT} random nonexistent paths...")
    codes = []
    for _ in range(BASELINE_PROBE_COUNT):
        route = f"/rtsp-path-locator-{secrets.token_hex(8)}"
        code, reason = probe_route(host, port, route, timeout)
        codes.append(code)
        print(f"  {code if code is not None else reason} {route}")

    known = [c for c in codes if c is not None]
    if not known:
        print("Baseline inconsistent: got no response to any baseline probe; treating any response as interesting.\n")
        return None

    baseline = max(set(known), key=known.count)
    if len(set(known)) > 1:
        print(f"Warning: baseline probes returned inconsistent codes {sorted(set(known))}; using the most common ({baseline}) as the baseline.\n")
    else:
        print(f"Baseline status code for nonexistent paths: {baseline}\n")
    return baseline


def classify(code, baseline):
    """Classify a probe result against the baseline status code.
    Args:
        code: Status code returned by probe_route, or None on error.
        baseline: Status code established by establish_baseline for a known
            nonexistent path, or None if no consistent baseline was found.
    Returns:
        "!" if code is None (network error, timeout, or unparseable
        response); "-" if code matches the baseline (looks invalid); "+"
        otherwise (differs from baseline, so it looks interesting/valid).
    """
    if code is None:
        return "!"
    if code == baseline:
        return "-"
    return "+"


def format_result(marker, code_or_reason, route):
    """Format one probe result as a single printable/loggable line.
    Args:
        marker: Classification marker for the route ("+", "-", or "!"), as
            produced by classify.
        code_or_reason: The status code (int) or the error/reason text (str)
            to display alongside the route.
        route: The candidate RTSP path that was probed.
    Returns:
        A line of the form "[marker] code_or_reason route".
    """
    return f"[{marker}] {code_or_reason} {route}"


def main():
    """Parse CLI arguments and drive the baseline calibration and route-probing scan.
    Reads the routes file, establishes the server's baseline status code,
    probes every route, prints/writes a marked result line for each one
    (subject to --verbose), and finishes with a summary count.
    Args:
        None. Arguments are read from sys.argv via argparse.
    Returns:
        None. Exits the process with status 1 if the routes file can't be
        read; otherwise returns normally after printing the summary.
    """
    parser = argparse.ArgumentParser(description="Locate valid RTSP paths on a server by sending DESCRIBE requests.")
    parser.add_argument("-H", "--host", required=True, help="target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=554, help="RTSP port (default: 554)")
    parser.add_argument("-r", "--routes", required=True, help="file with candidate RTSP paths, one per line")
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="delay in seconds between requests (default: 0)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="per-request socket timeout in seconds (default: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="also show invalid/rejected paths")
    parser.add_argument("-o", "--output", help="write results to this file in addition to stdout")
    args = parser.parse_args()

    try:
        routes = read_routes(args.routes)
    except OSError as e:
        print(f"error: could not read routes file: {e}", file=sys.stderr)
        sys.exit(1)

    out = open(args.output, "w", encoding="utf-8") if args.output else None

    def emit(line):
        print(line)
        if out:
            out.write(line + "\n")

    baseline = establish_baseline(args.host, args.port, args.timeout)

    valid = invalid = errors = 0
    try:
        for i, route in enumerate(routes):
            code, reason = probe_route(args.host, args.port, route, args.timeout)
            marker = classify(code, baseline)

            if marker == "+":
                valid += 1
                emit(format_result("+", code, route))
            elif marker == "-":
                invalid += 1
                if args.verbose:
                    emit(format_result("-", code, route))
            else:
                errors += 1
                emit(format_result("!", reason, route))

            if args.delay and i < len(routes) - 1:
                time.sleep(args.delay)
    finally:
        if out:
            out.close()

    print()
    print(f"Tested: {len(routes)}")
    print(f"Valid/probable: {valid}")
    print(f"Invalid: {invalid}")
    print(f"Errors: {errors}")


if __name__ == "__main__":
    main()
