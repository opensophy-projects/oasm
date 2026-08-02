#!/usr/bin/env python3
"""Convert a curated payload text file into simple Snort HTTP content rules.

This is intended for small, reviewed payload sets or stable patterns. Do not turn
large raw wordlists into one-rule-per-line signature packs without review.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def snort_escape(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"').replace(';', '|3B|')


def iter_payloads(path: Path, limit: int | None):
    seen: set[str] = set()
    emitted = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, 1):
            payload = line.strip()
            if not payload or payload.startswith("#") or payload in seen:
                continue
            seen.add(payload)
            yield line_no, payload
            emitted += 1
            if limit is not None and emitted >= limit:
                return


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert curated payload lines to Snort HTTP content rules")
    parser.add_argument("--input", required=True, type=Path, help="Curated payload text file")
    parser.add_argument("--output", required=True, type=Path, help="Output .rules file")
    parser.add_argument("--sid-start", type=int, default=9000000, help="First local SID to use")
    parser.add_argument("--msg-prefix", default="openappsec custom payload", help="Rule message prefix")
    parser.add_argument("--http-buffer", choices=("http_uri", "http_client_body", "http_header"), default="http_uri")
    parser.add_argument("--limit", type=int, help="Stop after N unique payloads")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Input file does not exist: {args.input}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.output.open("w", encoding="utf-8") as out:
        out.write("# Generated from a curated payload file. Review before production use.\n")
        out.write(f"# source: {args.input}\n")
        for index, (line_no, payload) in enumerate(iter_payloads(args.input, args.limit)):
            sid = args.sid_start + index
            escaped = snort_escape(payload)
            msg = snort_escape(f"{args.msg_prefix} line {line_no}")
            out.write(
                f'alert http any any -> any any (msg:"{msg}"; flow:to_server; '
                f'content:"{escaped}"; {args.http_buffer}; '
                f'classtype:web-application-attack; sid:{sid}; rev:1;)\n'
            )
            count += 1

    print(f"rules={count}")
    print(f"output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
