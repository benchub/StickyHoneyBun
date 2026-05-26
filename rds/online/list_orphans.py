#!/usr/bin/env python3
"""
list_orphans.py — list AWS resources tagged sticky_honey_bun_test_id in
the current region, grouped by run_id.

This is the safety-net inspector for when a setup or test crashed
before its cleanup code ran. For each run_id present, it prints the
resources and the exact teardown command to remove them. Deletion lives
in teardown.py so there's only one destructive code path to audit.

USAGE: python3 rds/online/list_orphans.py
"""

import os
import sys
from collections import defaultdict

from botocore.exceptions import BotoCoreError, ClientError

import aws_discovery

TAG_KEY = aws_discovery.TAG_KEY


def main():
    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        print("list_orphans: AWS_REGION must be set", file=sys.stderr)
        sys.exit(1)

    by_run = defaultdict(list)
    try:
        for kind, entries in aws_discovery.find_all(region).items():
            for arn, _id, tag_val in entries:
                by_run[tag_val].append(arn)
    except (BotoCoreError, ClientError) as e:
        print(f"list_orphans: enumeration failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not by_run:
        print(f"list_orphans: no resources tagged {TAG_KEY} in {region}")
        return

    total = sum(len(v) for v in by_run.values())
    print(
        f"list_orphans: found {total} resource(s) tagged {TAG_KEY} in "
        f"{region}, across {len(by_run)} run(s):\n"
    )
    for run_id in sorted(by_run):
        print(f"run_id={run_id}  ({len(by_run[run_id])} resource(s)):")
        for arn in by_run[run_id]:
            print(f"  {arn}")
        print(f"  →  python3 rds/online/teardown.py {run_id}")
        print()


if __name__ == "__main__":
    main()
