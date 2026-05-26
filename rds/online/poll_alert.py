#!/usr/bin/env python3
"""
poll_alert.py — wait for a Lambda CloudWatch log entry matching a needle.

USAGE: python3 poll_alert.py <log_group> <needle> [--timeout=60]

Exits 0 if a log event containing <needle> is found within the timeout,
1 otherwise. Used by run.pl to verify that triggering a trap actually
caused the Lambda to receive (and log) the alert.

Lambda invocation is async ("Event" invocation type), and CloudWatch
ingest end-to-end latency on a cold Lambda + a freshly-created log
group can run 30-90 seconds in practice (observed on db.t4g.micro RDS
with a freshly-deployed Lambda). Callers should pass a generous timeout
on the first probe of a run; subsequent probes against the warm Lambda
typically resolve in under 15 seconds. The needle is a substring
search — `filter-log-events` treats it as a CloudWatch Logs filter
pattern.
"""

import argparse
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_group")
    ap.add_argument("needle")
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        print("poll_alert: AWS_REGION must be set", file=sys.stderr)
        sys.exit(2)

    client = boto3.client("logs", region_name=region)
    # Search log events from the last 5 minutes to be tolerant of clock skew.
    start_ms = int((time.time() - 300) * 1000)
    deadline = time.time() + args.timeout

    while time.time() < deadline:
        try:
            resp = client.filter_log_events(
                logGroupName=args.log_group,
                startTime=start_ms,
                filterPattern=f'"{args.needle}"',
                limit=10,
            )
        except ClientError as e:
            # Log group may not exist yet on the first poll (Lambda's first
            # invocation creates it). Retry rather than fail.
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(2)
                continue
            raise

        if resp.get("events"):
            for ev in resp["events"]:
                if args.needle in ev["message"]:
                    print(ev["message"].strip())
                    return
        time.sleep(2)

    print(
        f"poll_alert: did not find {args.needle!r} in {args.log_group} "
        f"within {args.timeout}s",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
