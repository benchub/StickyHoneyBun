#!/usr/bin/env python3
"""
Sticky Honey Bun alert monitor (reference implementation).

Tails the alert log file, parses JSON event lines, applies suppression rules,
tracks heartbeat freshness, and on a genuine alert revokes login from the
offending role and terminates its sessions on the configured primary.

This is a reference. Adapt to your environment, monitoring stack, and
incident-response playbook.

Dependencies: pyyaml, psycopg2 (or psycopg2-binary).
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import yaml

try:
    import psycopg2
    from psycopg2 import sql
except ImportError:
    psycopg2 = None
    sql = None


LOG = logging.getLogger("shb-monitor")


@dataclass
class Suppression:
    session_user: Optional[str] = None
    current_user: Optional[str] = None
    client_addr: Optional[str] = None
    tag: Optional[str] = None
    note: str = ""

    def matches(self, event: dict) -> bool:
        for key in ("session_user", "current_user", "client_addr", "tag"):
            expected = getattr(self, key)
            if expected is None:
                continue
            if event.get(key) != expected:
                return False
        # An empty Suppression matches everything; reject that case.
        return any(
            getattr(self, k) is not None
            for k in ("session_user", "current_user", "client_addr", "tag")
        )


@dataclass
class Config:
    log_path: Path
    primary_dsn: Optional[str] = None
    suppressions: list[Suppression] = field(default_factory=list)
    heartbeat_max_age_seconds: int = 300
    dry_run: bool = True
    webhook_url: Optional[str] = None
    poll_interval_seconds: float = 1.0
    heartbeat_tag_prefix: str = "sticky_honey_bun.heartbeat"

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        data = yaml.safe_load(path.read_text())
        return cls(
            log_path=Path(data["log_path"]).expanduser(),
            primary_dsn=data.get("primary_dsn"),
            suppressions=[Suppression(**s) for s in data.get("suppressions", [])],
            heartbeat_max_age_seconds=int(data.get("heartbeat_max_age_seconds", 300)),
            dry_run=bool(data.get("dry_run", True)),
            webhook_url=data.get("webhook_url"),
            poll_interval_seconds=float(data.get("poll_interval_seconds", 1.0)),
            heartbeat_tag_prefix=data.get(
                "heartbeat_tag_prefix", "sticky_honey_bun.heartbeat"
            ),
        )


class StopFlag:
    def __init__(self) -> None:
        self.value = False


def tail_lines(path: Path, poll: float, stop: StopFlag) -> Iterator[Optional[str]]:
    """Yield new lines as they appear, or None on each idle tick."""
    while not stop.value:
        if not path.exists():
            yield None
            time.sleep(poll)
            continue
        with path.open() as fh:
            fh.seek(0, os.SEEK_END)
            try:
                inode = os.fstat(fh.fileno()).st_ino
            except OSError:
                inode = None
            while not stop.value:
                line = fh.readline()
                if line:
                    yield line.rstrip("\n")
                else:
                    yield None
                    try:
                        if inode is not None and path.stat().st_ino != inode:
                            break
                    except FileNotFoundError:
                        break
                    time.sleep(poll)
        time.sleep(poll)


def parse_ts(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def is_heartbeat(event: dict, cfg: Config) -> bool:
    if event.get("event") == "heartbeat":
        return True
    tag = event.get("tag") or ""
    return tag.startswith(cfg.heartbeat_tag_prefix)


def post_webhook(url: str, event: dict) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(event).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        LOG.error("webhook failed: %s", e)


def revoke_and_terminate(cfg: Config, event: dict) -> None:
    if cfg.dry_run:
        LOG.info(
            "dry_run=true; would REVOKE LOGIN from role=%s and terminate its sessions",
            event.get("session_user"),
        )
        return

    if psycopg2 is None:
        LOG.error("psycopg2 not installed; cannot perform action")
        return

    if not cfg.primary_dsn:
        LOG.error("no primary_dsn configured; cannot perform action")
        return

    role = event.get("session_user")
    if not role:
        LOG.error("event missing session_user; cannot perform action")
        return

    try:
        conn = psycopg2.connect(cfg.primary_dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(role))
            )
            cur.execute(
                """
                SELECT pg_terminate_backend(pid)
                  FROM pg_stat_activity
                 WHERE usename = %s
                """,
                (role,),
            )
            terminated = cur.rowcount
        conn.close()
        LOG.warning(
            "revoked LOGIN from role=%s and terminated %d session(s)",
            role,
            terminated,
        )
    except Exception as e:
        LOG.error("response action failed: %s", e)


def respond(event: dict, cfg: Config) -> None:
    LOG.warning("ALERT %s", json.dumps(event, sort_keys=True))
    if cfg.webhook_url:
        post_webhook(cfg.webhook_url, event)
    revoke_and_terminate(cfg, event)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", "-c", required=True, type=Path)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    cfg = Config.from_file(args.config)
    LOG.info("watching %s", cfg.log_path)
    LOG.info(
        "dry_run=%s suppressions=%d heartbeat_max_age=%ds",
        cfg.dry_run, len(cfg.suppressions), cfg.heartbeat_max_age_seconds,
    )

    stop = StopFlag()

    def _stop(*_args):
        LOG.info("shutdown requested")
        stop.value = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    last_heartbeat: Optional[datetime] = None
    deadman_alerted = False

    def check_deadman() -> None:
        nonlocal deadman_alerted
        if last_heartbeat is None:
            return
        age = (datetime.now(timezone.utc) - last_heartbeat).total_seconds()
        if age > cfg.heartbeat_max_age_seconds and not deadman_alerted:
            LOG.error(
                "DEADMAN: no heartbeat for %.0f seconds (threshold %d)",
                age, cfg.heartbeat_max_age_seconds,
            )
            deadman_alerted = True
            if cfg.webhook_url:
                post_webhook(cfg.webhook_url, {
                    "event": "deadman",
                    "last_heartbeat": last_heartbeat.isoformat(),
                    "age_seconds": age,
                })

    for item in tail_lines(cfg.log_path, cfg.poll_interval_seconds, stop):
        if item is None:
            check_deadman()
            continue

        try:
            event = json.loads(item)
        except json.JSONDecodeError:
            LOG.error("malformed line: %s", item)
            continue

        if is_heartbeat(event, cfg):
            ts = parse_ts(event.get("ts", ""))
            if ts is not None:
                if deadman_alerted:
                    LOG.info("heartbeat resumed at %s", ts.isoformat())
                last_heartbeat = ts
                deadman_alerted = False
            continue

        suppressed_by = next(
            (s for s in cfg.suppressions if s.matches(event)),
            None,
        )

        if suppressed_by:
            LOG.info(
                "suppressed by %r: tag=%s session_user=%s client=%s",
                suppressed_by.note or "rule",
                event.get("tag"),
                event.get("session_user"),
                event.get("client_addr"),
            )
            continue

        respond(event, cfg)

    LOG.info("exit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
