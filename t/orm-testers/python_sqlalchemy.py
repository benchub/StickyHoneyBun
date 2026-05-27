#!/usr/bin/env python3
"""
ORM tester: SQLAlchemy 2.x (most popular general-purpose Python ORM).

We reflect the table's schema (autoload) so SQLAlchemy sees `honey` as
its actual PG type — same path application code would take when an
existing table is mapped without a hand-written model. The `.all()`
fetch issues `SELECT id, honey FROM honey_table ...` over the text
protocol; typeoutput fires for the honey column and the trap logs an
alert.

Connects via libpq env vars (PGHOST / PGPORT / PGDATABASE / PGUSER).
"""
import os
import sys

import sqlalchemy as sa

# Use the dialect's empty-url form so libpq env vars drive the connection.
engine = sa.create_engine("postgresql+psycopg2://", connect_args={})

with engine.connect() as conn:
    md = sa.MetaData()
    t = sa.Table("honey_table", md, autoload_with=conn)
    rows = conn.execute(sa.select(t).order_by(t.c.id)).all()
    sys.stderr.write(
        f"sqlalchemy: fetched {len(rows)} row(s); "
        f"first honey value = {rows[0].honey if rows else 'none'!r}\n"
    )
