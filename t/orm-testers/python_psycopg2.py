#!/usr/bin/env python3
"""
ORM tester: psycopg2 (Python's direct libpq binding — baseline path).

Not strictly an ORM, but it's the layer most Python ORMs build on, and
any behavioral difference between this and the higher-level ORMs
isolates the ORM layer. We expect this to fire the trap: it issues a
plain SELECT via libpq's text protocol, which dispatches typeoutput
exactly like psql does.

Connects via libpq env vars (PGHOST / PGPORT / PGDATABASE / PGUSER)
set by the driving test. Reads the planted honey row, prints what it
got, exits 0 on success.
"""
import os
import sys

import psycopg2

with psycopg2.connect("") as conn:    # all params from env
    with conn.cursor() as cur:
        cur.execute("SELECT id, honey FROM honey_table ORDER BY id")
        rows = cur.fetchall()
        sys.stderr.write(
            f"psycopg2: fetched {len(rows)} row(s); "
            f"first honey value = {rows[0][1] if rows else 'none'!r}\n"
        )
