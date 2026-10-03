#!/usr/bin/env python3
"""Estimate a node's available bandwidth once, before enabling VPN traffic.

Uses ~382 MiB of synthetic traffic against Cloudflare's public speed test APIs.
The result is an estimate of this route at this time, not the provider's contract.
Never run automatically during daemon startup. No VPN data is sent to the test API.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time
from urllib.parse import urlsplit

DOWNLOAD = "https://speed.cloudflare.com/__down"
UPLOAD = "https://speed.cloudflare.com/__up"
SAMPLE_BYTES = 25_000_000  # A standard measurement size used by the public API.
CHUNK = bytes(64 * 1024)


def endpoint(url):
    value = urlsplit(url)
    if (value.scheme != "https" or not value.hostname or value.username
            or value.password or value.query or value.fragment):
        raise ValueError("Speed test endpoints must be HTTPS URLs without credentials or query strings")
    return value


def transfer(url, size, upload):
    target = endpoint(url)
    connection = http.client.HTTPSConnection(target.hostname, target.port, timeout=5)
    deadline = time.monotonic() + 30
    try:
        path = target.path or "/"
        if upload:
            connection.putrequest("POST", path)
            connection.putheader("Content-Length", str(size))
            connection.putheader("Content-Type", "application/octet-stream")
            connection.endheaders()
            remaining = size
            while remaining:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Upload sample exceeded 30 seconds")
                count = min(remaining, len(CHUNK))
                connection.send(CHUNK[:count])
                remaining -= count
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError(f"Upload API returned HTTP {response.status}")
            response.read(64 * 1024)
        else:
            connection.request("GET", f"{path}?bytes={size}", headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError(f"Download API returned HTTP {response.status}, encoding {response.getheader('Content-Encoding', 'identity')}")
            remaining = size
            while remaining:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Download sample exceeded 30 seconds")
                data = response.read(min(remaining, len(CHUNK)))
                if not data:
                    raise ValueError("Download API returned a truncated sample")
                remaining -= len(data)
    finally:
        connection.close()
    return size


def sample(url, upload, size=SAMPLE_BYTES, transfer_fn=transfer):
    # Two independent connections reduce the effect of a single TCP flow.
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(transfer_fn, url, size, upload) for _ in range(2)]
        transferred = sum(job.result() for job in jobs)
    elapsed = time.monotonic() - started
    if transferred != size * 2 or elapsed <= 0:
        raise ValueError("Incomplete bandwidth sample")
    return transferred * 8 / elapsed / 1_000_000


def choose_limit(download, upload, headroom=0.9):
    if not 0.5 <= headroom <= 0.95:
        raise ValueError("Headroom must be between 0.5 and 0.95")
    for values in [download, upload]:
        if len(values) != 3 or any(not math.isfinite(v) or v <= 0 for v in values):
            raise ValueError("Three successful samples in each direction are required")
        if max(values) / min(values) > 2:
            raise ValueError("Unstable measurements; retry during a quiet period or set a manual budget")
    measured = min(statistics.median(download), statistics.median(upload))
    limit = math.floor(measured * headroom)
    if not 1 <= limit <= 100_000:
        raise ValueError("Measurement is outside the supported range; set a manual budget")
    return limit


def measure(download_url=DOWNLOAD, upload_url=UPLOAD, headroom=0.9):
    if not 0.5 <= headroom <= 0.95:
        raise ValueError("Headroom must be between 0.5 and 0.95")
    endpoint(download_url)
    endpoint(upload_url)
    print("Measuring bandwidth: up to ~382 MiB of synthetic traffic; do this before serving users.", file=sys.stderr)
    results = []
    for url, upload in [(download_url, False), (upload_url, True)]:
        sample(url, upload)  # Warm up with a full sample before judging stability.
        values = [sample(url, upload) for _ in range(3)]
        results.append(values)
        print(json.dumps({"direction": "upload" if upload else "download",
                          "samples_mbps": values}), file=sys.stderr)
    return {"bandwidth_mbps": choose_limit(*results, headroom),
            "download_mbps": results[0], "upload_mbps": results[1],
            "headroom": headroom, "measured_at": int(time.time())}


def traffic_config(mbps):
    return f"\n[traffic]\n# Aggregate VPN budget; all active accounts share spare capacity.\nbandwidth_mbps = {mbps}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-url", default=DOWNLOAD)
    parser.add_argument("--upload-url", default=UPLOAD)
    parser.add_argument("--headroom", type=float, default=0.9)
    parser.add_argument("--output", type=Path, help="Create a new TOML snippet; refuses to replace an existing file")
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error("Output already exists")
    try:
        result = measure(args.download_url, args.upload_url, args.headroom)
        print(json.dumps(result), file=sys.stderr)
        config = traffic_config(result["bandwidth_mbps"])
        if args.output:
            with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                output.write(config)
        else:
            print(config, end="")
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, f"Bandwidth measurement failed: {error}\nNo budget was saved. Retry or configure bandwidth_mbps manually.\n")


if __name__ == "__main__":
    main()
