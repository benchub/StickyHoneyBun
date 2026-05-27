#!/usr/bin/env python3
"""
ORM tester: Django ORM.

Django requires a settings module + AppConfig before models work, so
we configure it inline (no settings.py file needed). The Model maps
to the `honey_table` already created by the driving test. The
`.objects.all()` call is the natural "fetch all rows" idiom; it
compiles to `SELECT id, honey FROM honey_table` and fetches via the
text protocol.

Connects via libpq env vars.
"""
import os
import sys

import django
from django.conf import settings

settings.configure(
    DEBUG=False,
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME":     os.environ.get("PGDATABASE", "postgres"),
            "USER":     os.environ.get("PGUSER", ""),
            "PASSWORD": os.environ.get("PGPASSWORD", ""),
            "HOST":     os.environ.get("PGHOST", ""),
            "PORT":     os.environ.get("PGPORT", ""),
        },
    },
    INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
    USE_TZ=True,
)
django.setup()

from django.db import models

class HoneyTable(models.Model):
    honey = models.TextField()
    class Meta:
        app_label = "shb_test"
        db_table = "honey_table"
        managed = False

rows = list(HoneyTable.objects.all().order_by("id"))
sys.stderr.write(
    f"django: fetched {len(rows)} row(s); "
    f"first honey value = {rows[0].honey if rows else 'none'!r}\n"
)
