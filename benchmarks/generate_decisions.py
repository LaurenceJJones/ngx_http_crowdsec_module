#!/usr/bin/env python3
"""Generate a stream decisions payload with N synthetic ban entries."""

import json
import sys


def main() -> None:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    decisions = [
        {
            "type": "ban",
            "scope": "ip",
            "value": f"203.0.{i // 256}.{i % 256}",
            "duration": "24h",
            "scenario": "bench",
        }
        for i in range(count)
    ]
    json.dump({"new": decisions, "deleted": []}, sys.stdout)


if __name__ == "__main__":
    main()
