#!/usr/bin/env python3
"""Replay payload files against an authorized open-appsec-protected endpoint.

This tool is intentionally simple and noisy: it adds run/payload headers so the
requests can be correlated in open-appsec/NPM logs, rate-limits by default, and
requires an explicit authorization flag before sending traffic.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Iterable
from urllib import error, parse, request


def iter_payloads(paths: list[Path], limit: int | None) -> Iterable[tuple[str, Path, int]]:
    emitted = 0
    seen: set[str] = set()
    for path in paths:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_no, line in enumerate(handle, 1):
                payload = line.strip()
                if not payload or payload.startswith("#") or payload in seen:
                    continue
                seen.add(payload)
                yield payload, path, line_no
                emitted += 1
                if limit is not None and emitted >= limit:
                    return


def build_get_url(base_url: str, param_name: str, payload: str) -> str:
    parts = parse.urlsplit(base_url)
    query = parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((param_name, payload))
    return parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parse.urlencode(query), parts.fragment))


def send_request(args: argparse.Namespace, payload: str, payload_id: str, run_id: str) -> tuple[int | None, str | None, int]:
    headers = {
        "User-Agent": args.user_agent,
        "X-OAS-Test-Run": run_id,
        "X-OAS-Payload-Id": payload_id,
        "X-OAS-Expected-Label": args.expected_label,
    }
    for header in args.header:
        name, sep, value = header.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"Invalid header {header!r}; expected 'Name: value'")
        headers[name.strip()] = value.strip()

    if args.method == "GET":
        url = build_get_url(args.base_url, args.param, payload)
        data = None
    else:
        url = args.base_url
        body = parse.urlencode({args.param: payload}).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        data = body

    req = request.Request(url, data=data, headers=headers, method=args.method)
    try:
        with request.urlopen(req, timeout=args.timeout) as response:
            response.read(1024)
            return response.status, None, len(data or b"")
    except error.HTTPError as exc:
        exc.read(1024)
        return exc.code, None, len(data or b"")
    except Exception as exc:  # network errors should be reported per payload
        return None, f"{type(exc).__name__}: {exc}", len(data or b"")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay labeled payloads against an authorized open-appsec endpoint")
    parser.add_argument("--base-url", required=True, help="Target URL, for example https://app.example.com/search")
    parser.add_argument("--payload-file", action="append", required=True, type=Path, help="Payload file; can be repeated")
    parser.add_argument("--param", default="q", help="Parameter name used for GET query or POST form body")
    parser.add_argument("--method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--expected-label", choices=("true-positive", "false-positive"), default="true-positive")
    parser.add_argument("--rate", type=float, default=2.0, help="Maximum requests per second")
    parser.add_argument("--limit", type=int, help="Stop after N unique payloads")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--header", action="append", default=[], help="Extra header as 'Name: value'; can be repeated")
    parser.add_argument("--user-agent", default="openappsec-payload-runner/1.0")
    parser.add_argument("--run-id", default=f"oas-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--output", type=Path, default=Path("payload-run-results.jsonl"))
    parser.add_argument("--i-am-authorized", action="store_true", help="Required: confirms this target is yours/authorized")
    args = parser.parse_args()

    if not args.i_am_authorized:
        print("Refusing to send traffic without --i-am-authorized", file=sys.stderr)
        return 2
    if args.rate <= 0:
        print("--rate must be greater than zero", file=sys.stderr)
        return 2

    delay = 1.0 / args.rate
    args.output.parent.mkdir(parents=True, exist_ok=True)
    csv_path = args.output.with_suffix(".csv")

    with args.output.open("w", encoding="utf-8") as jsonl, csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["run_id", "payload_id", "source_file", "source_line", "expected_label", "method", "status", "error"],
        )
        writer.writeheader()
        for index, (payload, source_file, source_line) in enumerate(iter_payloads(args.payload_file, args.limit), 1):
            payload_id = f"{args.run_id}-{index:06d}"
            status, err, _ = send_request(args, payload, payload_id, args.run_id)
            row = {
                "run_id": args.run_id,
                "payload_id": payload_id,
                "source_file": str(source_file),
                "source_line": source_line,
                "expected_label": args.expected_label,
                "method": args.method,
                "status": status,
                "error": err,
            }
            jsonl.write(json.dumps(row, ensure_ascii=False) + "\n")
            jsonl.flush()
            writer.writerow(row)
            csv_file.flush()
            print(json.dumps(row, ensure_ascii=False))
            time.sleep(delay)

    print(f"run_id={args.run_id}")
    print(f"jsonl={args.output}")
    print(f"csv={csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
