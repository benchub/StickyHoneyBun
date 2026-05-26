#!/usr/bin/env python3
"""
preflight.py — verify the environment is ready for an RDS online test run.

Refuses to proceed unless:
  - All required AWS credential env vars are set.
  - AWS_SESSION_EXPIRATION has at least SHB_TEST_MIN_MINUTES (default 10)
    of life left at start. Sessions are capped at 60 minutes so this is
    just the required buffer.
  - SHB_TEST_VPC_ID and SHB_TEST_SUBNET_IDS are set. The test cannot pick
    these safely (must be operator-controlled subnets that allow public
    RDS access and won't surprise anyone).
  - No AWS resources in the configured region currently bear the tag
    `sticky_honey_bun_test_id`. A non-empty result means a prior test
    run leaked resources; the operator must inspect (`list_orphans.py`)
    and clean them up before this run can safely proceed.
  - The operator's external IP can be determined (or has been overridden
    via SHB_TEST_OPERATOR_IP).

Emits a single JSON object on stdout with the values downstream scripts
need (region, operator_ip, parsed extra tags, etc.). Diagnostic and
failure messages go to stderr.

Exit codes:
  0  preflight passed
  1  missing / invalid environment
  2  session expires too soon
  3  stale resources detected
  4  external IP detection failed
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

import aws_discovery

TAG_KEY = "sticky_honey_bun_test_id"


def fail(code, message):
    print(f"preflight: {message}", file=sys.stderr)
    sys.exit(code)


def require_env(name):
    v = os.environ.get(name)
    if not v:
        fail(1, f"missing required env var: {name}")
    return v


def parse_extra_tags(spec):
    """Parse 'k1=v1,k2=v2' into a dict. Empty / None → {}."""
    if not spec:
        return {}
    out = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            fail(1, f"SHB_TEST_TAGS entry missing '=': {item!r}")
        k, v = item.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k:
            fail(1, f"SHB_TEST_TAGS entry has empty key: {item!r}")
        if k.lower().startswith("sticky_honey_bun_test"):
            fail(
                1,
                f"SHB_TEST_TAGS cannot redefine reserved key {k!r}; the "
                "sticky_honey_bun_test_* tag namespace is managed by the "
                "test harness",
            )
        out[k] = v
    return out


def check_session_expiration(min_minutes):
    exp = require_env("AWS_SESSION_EXPIRATION")
    try:
        if exp.endswith("Z"):
            exp_iso = exp[:-1] + "+00:00"
        else:
            exp_iso = exp
        deadline = datetime.fromisoformat(exp_iso)
    except ValueError:
        fail(1, f"AWS_SESSION_EXPIRATION is not parseable ISO 8601: {exp!r}")
    now = datetime.now(timezone.utc)
    remaining = (deadline - now).total_seconds() / 60
    if remaining < min_minutes:
        fail(
            2,
            f"AWS session expires in {remaining:.1f} min; "
            f"need at least {min_minutes} min buffer "
            "(lower SHB_TEST_MIN_MINUTES to bypass, but plan for the "
            "test to time out mid-flight)",
        )
    return remaining


def detect_operator_ip():
    override = os.environ.get("SHB_TEST_OPERATOR_IP")
    if override:
        return override
    urls = [
        "https://checkip.amazonaws.com",
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "shb-preflight"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                ip = r.read().decode().strip()
                # Sanity: IPv6 textual max is 39 chars; reject anything wild.
                if ip and len(ip) <= 45 and " " not in ip:
                    return ip
        except Exception:
            continue
    fail(
        4,
        "could not detect external IP from checkip.amazonaws.com / "
        "ipify.org / ifconfig.me; set SHB_TEST_OPERATOR_IP=a.b.c.d to bypass",
    )


def list_stale_resources(region):
    """Find any resource carrying our tag (any value) via per-service
    enumeration. Returns a list of (resource_arn, tag_value) tuples."""
    try:
        by_kind = aws_discovery.find_all(region, run_id_filter=None)
    except (BotoCoreError, ClientError) as e:
        fail(1, f"failed to enumerate resources: {e}")
    stale = []
    for kind, entries in by_kind.items():
        for arn, _ident, tag_val in entries:
            stale.append((arn, tag_val))
    return stale


def verify_auth():
    """Verify AWS auth works, whether via explicit env vars or a profile.
    Calls sts:GetCallerIdentity to confirm the credentials resolve."""
    has_env = all(
        os.environ.get(v) for v in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        )
    )
    has_profile = bool(os.environ.get("AWS_PROFILE"))
    if not (has_env or has_profile):
        fail(
            1,
            "no AWS auth: set AWS_PROFILE, or all of "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_SESSION_TOKEN",
        )
    try:
        sts = boto3.client("sts")
        return sts.get_caller_identity()["Arn"]
    except (BotoCoreError, ClientError) as e:
        fail(1, f"AWS auth check (sts:GetCallerIdentity) failed: {e}")


def main():
    caller_arn = verify_auth()

    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        fail(1, "AWS_REGION (or AWS_DEFAULT_REGION) must be set")

    vpc_id = require_env("SHB_TEST_VPC_ID")
    subnet_ids_raw = require_env("SHB_TEST_SUBNET_IDS")
    subnet_ids = [s.strip() for s in subnet_ids_raw.split(",") if s.strip()]
    if len(subnet_ids) < 2:
        fail(
            1,
            "SHB_TEST_SUBNET_IDS must list at least 2 subnets in different "
            "AZs (RDS DB subnet group requirement)",
        )

    try:
        min_minutes = int(os.environ.get("SHB_TEST_MIN_MINUTES", "10"))
    except ValueError:
        fail(1, "SHB_TEST_MIN_MINUTES must be an integer (minutes)")
    instance_class = os.environ.get("SHB_TEST_INSTANCE_CLASS", "db.t4g.micro")
    extra_tags = parse_extra_tags(os.environ.get("SHB_TEST_TAGS"))

    # AWS_SESSION_EXPIRATION is optional: it's typically set by aws-vault /
    # awscli SSO export, but a plain AWS_PROFILE setup doesn't populate it.
    # If present, enforce the buffer. If absent, warn and proceed (the
    # operator vouched for their session length by running us).
    if os.environ.get("AWS_SESSION_EXPIRATION"):
        session_remaining = check_session_expiration(min_minutes)
    else:
        session_remaining = None
        print(
            "preflight: AWS_SESSION_EXPIRATION not set — cannot enforce "
            "session-time buffer. Make sure your session has >= "
            f"{min_minutes} minutes left; on expiry, end-of-test teardown "
            "will fail and you'll need `make rds-list-orphans` to recover.",
            file=sys.stderr,
        )
    operator_ip = detect_operator_ip()
    stale = list_stale_resources(region)

    if stale:
        print(
            f"preflight: found {len(stale)} stale resource(s) tagged "
            f"{TAG_KEY} in {region}:",
            file=sys.stderr,
        )
        for arn, tag_val in stale[:20]:
            print(f"  {arn}  (id={tag_val})", file=sys.stderr)
        if len(stale) > 20:
            print(f"  ... and {len(stale) - 20} more", file=sys.stderr)
        fail(
            3,
            "refuse to start until these are reviewed and removed. "
            "Run `python3 rds/online/list_orphans.py` to inspect and delete.",
        )

    out = {
        "region": region,
        "vpc_id": vpc_id,
        "subnet_ids": subnet_ids,
        "instance_class": instance_class,
        "operator_ip": operator_ip,
        "session_minutes_remaining":
            round(session_remaining, 1) if session_remaining is not None else None,
        "caller_arn": caller_arn,
        "extra_tags": extra_tags,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
