#!/usr/bin/env python3
"""
poll_alert.py — query CloudWatch logs for events matching a needle.

USAGE:
    python3 poll_alert.py <log_group> <needle> [--timeout=60]
    python3 poll_alert.py <log_group> <needle> --count [--since=300]

Two modes:

WAIT MODE (default):
    Exits 0 if a log event containing <needle> is found within the
    timeout, 1 otherwise. The matching event's message is printed to
    stdout. Used to verify that triggering a trap caused the Lambda
    to receive (and log) the alert.

    Lambda invocation is async ("Event" invocation type), and CloudWatch
    ingest end-to-end latency on a cold Lambda + a freshly-created log
    group can run 30-90 seconds in practice (observed on db.t4g.micro
    RDS with a freshly-deployed Lambda). Callers should pass a generous
    timeout on the first probe of a run; subsequent probes against the
    warm Lambda typically resolve in under 15 seconds.

COUNT MODE (--count):
    One-shot. Counts events containing <needle> in the last `--since`
    seconds (default 300 = 5 minutes) and prints the count to stdout.
    Always exits 0 unless the log group genuinely doesn't exist.
    Used for negative assertions: "after this operation, exactly N
    new events matching this needle should exist." A typical pattern
    is to plant a sentinel with a unique tag, wait for it via WAIT
    MODE, then COUNT MODE the broader-needle-set to verify nothing
    extra fired.
"""

import argparse
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError


def cloudwatch_client():
    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        print("poll_alert: AWS_REGION must be set", file=sys.stderr)
        sys.exit(2)
    return boto3.client("logs", region_name=region)


def filter_events(client, log_group, needle, start_ms, hard_limit=200):
    """Return up to hard_limit events from log_group matching needle,
    starting from start_ms. Paginates through filter_log_events."""
    events = []
    next_token = None
    while True:
        kwargs = {
            "logGroupName": log_group,
            "startTime": start_ms,
            "filterPattern": f'"{needle}"',
            "limit": min(100, hard_limit - len(events)),
        }
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = client.filter_log_events(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                # Log group not yet created — treat as zero events.
                return []
            raise
        for ev in resp.get("events", []):
            if needle in ev["message"]:
                events.append(ev)
                if len(events) >= hard_limit:
                    return events
        next_token = resp.get("nextToken")
        if not next_token:
            return events


def wait_mode(args, client):
    start_ms = int((time.time() - 300) * 1000)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        events = filter_events(client, args.log_group, args.needle,
                               start_ms, hard_limit=10)
        if events:
            print(events[0]["message"].strip())
            return
        time.sleep(2)
    print(
        f"poll_alert: did not find {args.needle!r} in {args.log_group} "
        f"within {args.timeout}s",
        file=sys.stderr,
    )
    sys.exit(1)


def count_mode(args, client):
    start_ms = int((time.time() - args.since) * 1000)
    events = filter_events(client, args.log_group, args.needle, start_ms)
    print(len(events))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log_group")
    ap.add_argument("needle")
    ap.add_argument("--timeout", type=int, default=60,
                    help="WAIT MODE: seconds to keep polling")
    ap.add_argument("--count", action="store_true",
                    help="COUNT MODE: one-shot count instead of wait")
    ap.add_argument("--since", type=int, default=300,
                    help="COUNT MODE: how far back to look, in seconds")
    args = ap.parse_args()

    client = cloudwatch_client()
    if args.count:
        count_mode(args, client)
    else:
        wait_mode(args, client)


if __name__ == "__main__":
    main()
