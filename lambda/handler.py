"""
Sticky Honey Bun receiver Lambda (reference).

This Lambda receives a JSON event from the RDS PL/pgSQL variant's honey_bun
output function (invoked via aws_lambda.invoke). Its job is to normalize the
payload, drop it into the alert processor's sink, and optionally fan out to SNS / SQS
/ etc.

Payload contract
================

The RDS PL function sends a JSON object with these fields. Field order and
naming match the self-hosted C variant's log line, so a single downstream
alert processor handles both sources.

  ts               ISO-8601 UTC timestamp with microseconds, e.g.
                   "2026-05-25T04:11:36.205673Z".
  event            "read_text" or "read_binary" for trap trips; "heartbeat"
                   for keepalive events from the external poker (the PL
                   variant does not produce heartbeats on its own).
  tag              The stored honey_bun value (typically schema.table.column).
  session_user     The originally authenticated PG role.
  current_user     Effective role after any SET ROLE.
  application_name PG GUC; spoofable via PGAPPNAME; forensic only.
  database         Current PG database name.
  pid              PG backend PID.
  client_addr      Client IP address, or "local" for unix-socket sessions.
  query            The top-level SQL text (current_query()), or NULL.
  cluster_id       Identifier of the source cluster. Read from the
                   locked-down sticky_honey_bun.config table (key
                   'cluster_id'); falls back to inet_server_addr() then
                   "unknown".

Deployment
==========

Runtime:    python3.11+ (boto3 is bundled in the Lambda runtime)
Handler:    handler.lambda_handler
Memory:     128 MB is plenty
Timeout:    10 seconds (the invocation from PG is Event-type / fire-and-forget;
            you have until Lambda's max but a quick timeout helps catch
            misconfiguration)

IAM execution role needs:
  - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
    (CloudWatch Logs is the default sink.)
  - sns:Publish on the alert topic (if SHB_SNS_TOPIC_ARN is set).

The RDS instance's IAM role needs lambda:InvokeFunction on this Lambda's ARN.

Environment
===========

SHB_SNS_TOPIC_ARN  (optional) publish each alert here in addition to logging.
SHB_REQUIRE_FIELDS (optional) comma-separated list of fields that must be
                   present. Defaults to "ts,event,tag,session_user,cluster_id".
SHB_LOG_HEARTBEATS (optional) "true" to log heartbeats at INFO level; default
                   is to drop them silently (heartbeats are noise unless
                   you're debugging the pipeline).
"""

import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_DEFAULT_REQUIRED = "ts,event,tag,session_user,cluster_id"

_sns_topic_arn = os.environ.get("SHB_SNS_TOPIC_ARN")
_sns_client = boto3.client("sns") if _sns_topic_arn else None
_required_fields = [
    f.strip()
    for f in os.environ.get("SHB_REQUIRE_FIELDS", _DEFAULT_REQUIRED).split(",")
    if f.strip()
]
_log_heartbeats = os.environ.get("SHB_LOG_HEARTBEATS", "").lower() in ("1", "true", "yes")


def _validate(event: dict) -> list[str]:
    return [f for f in _required_fields if f not in event]


def _publish_sns(event: dict) -> None:
    if not _sns_client or not _sns_topic_arn:
        return
    try:
        _sns_client.publish(
            TopicArn=_sns_topic_arn,
            Subject=(
                f"SHB alert: tag={event.get('tag')} "
                f"role={event.get('session_user')} "
                f"cluster={event.get('cluster_id')}"
            )[:99],  # SNS subject is capped at 100 chars
            Message=json.dumps(event, indent=2, sort_keys=True),
        )
    except Exception as e:
        logger.error("SNS publish failed: %s", e)


def lambda_handler(event: dict, context: Any) -> dict:
    # The PL function sends the payload as the event itself, not wrapped.
    if not isinstance(event, dict):
        logger.error("event is not a dict: %r", event)
        return {"statusCode": 400, "body": "event must be a JSON object"}

    missing = _validate(event)
    if missing:
        logger.error("payload missing required fields %s: %s",
                     missing, json.dumps(event, sort_keys=True))
        return {"statusCode": 400, "body": f"missing fields: {missing}"}

    kind = event.get("event")

    # Use compact separators so the emitted JSON matches the self-hosted
    # C variant byte-for-byte. The README documents "Both variants ship
    # the same JSON event shape"; without this, json.dumps' default ", "
    # / ": " separators add whitespace that downstream consumers and
    # cross-variant regex assertions don't tolerate.
    compact = lambda obj: json.dumps(obj, sort_keys=True,
                                     separators=(',', ':'))

    if kind == "heartbeat":
        if _log_heartbeats:
            logger.info("shb_heartbeat %s", compact(event))
        return {"statusCode": 200, "body": "heartbeat"}

    # Trap trip. Log at WARNING so it stands out in CloudWatch metric filters.
    logger.warning("shb_alert %s", compact(event))
    _publish_sns(event)

    return {"statusCode": 200, "body": "alert recorded"}
