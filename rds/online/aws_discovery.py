"""
aws_discovery.py — find resources by sticky_honey_bun_test_id tag using
per-service AWS APIs, no Resource Groups Tagging API required.

We use the Tagging API normally, but some operator roles (DBA-style SSO
roles especially) don't have `tag:GetResources`. This module provides
the same functionality by:

  1. Enumerating resources of each service type we create (RDS instances,
     RDS subnet/parameter groups, Lambda functions, IAM roles, EC2 SGs).
  2. Filtering by name prefix `shbtest-` (every resource we create
     starts with that) to cut the list quickly.
  3. Fetching tags via the service's own tag-list API.
  4. Returning entries whose `sticky_honey_bun_test_id` tag matches
     (or any value, if no filter is given).

Returned shape matches what the previous tag-API code emitted:
    {
      'rds_db':       [(arn, identifier, tag_value), ...],
      'rds_subgrp':   [...],
      'rds_pg':       [...],
      'lambda':       [...],
      'iam_role':     [...],
      'ec2_sg':       [...],
    }

For preflight, call find_all(region, run_id_filter=None) to detect any
stale runs. For teardown, pass the run_id to scope to one run only.
"""

import boto3
from botocore.exceptions import ClientError

TAG_KEY = "sticky_honey_bun_test_id"
NAME_PREFIX = "shbtest-"


def _tag_matches(tags_dict, run_id_filter):
    """Return the tag value if the resource carries our tag (and matches
    the run_id_filter, if one was given). Return None otherwise."""
    val = tags_dict.get(TAG_KEY)
    if val is None:
        return None
    if run_id_filter is not None and val != run_id_filter:
        return None
    return val


def find_rds_instances(rds, run_id_filter=None):
    out = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for inst in page["DBInstances"]:
            ident = inst["DBInstanceIdentifier"]
            if not ident.startswith(NAME_PREFIX):
                continue
            arn = inst["DBInstanceArn"]
            tags = {
                t["Key"]: t["Value"]
                for t in rds.list_tags_for_resource(ResourceName=arn)[
                    "TagList"
                ]
            }
            val = _tag_matches(tags, run_id_filter)
            if val is not None:
                out.append((arn, ident, val))
    return out


def find_rds_subnet_groups(rds, run_id_filter=None):
    out = []
    for page in rds.get_paginator("describe_db_subnet_groups").paginate():
        for g in page["DBSubnetGroups"]:
            name = g["DBSubnetGroupName"]
            if not name.startswith(NAME_PREFIX):
                continue
            arn = g["DBSubnetGroupArn"]
            tags = {
                t["Key"]: t["Value"]
                for t in rds.list_tags_for_resource(ResourceName=arn)[
                    "TagList"
                ]
            }
            val = _tag_matches(tags, run_id_filter)
            if val is not None:
                out.append((arn, name, val))
    return out


def find_rds_parameter_groups(rds, run_id_filter=None):
    out = []
    for page in rds.get_paginator("describe_db_parameter_groups").paginate():
        for g in page["DBParameterGroups"]:
            name = g["DBParameterGroupName"]
            if not name.startswith(NAME_PREFIX):
                continue
            arn = g["DBParameterGroupArn"]
            tags = {
                t["Key"]: t["Value"]
                for t in rds.list_tags_for_resource(ResourceName=arn)[
                    "TagList"
                ]
            }
            val = _tag_matches(tags, run_id_filter)
            if val is not None:
                out.append((arn, name, val))
    return out


def find_lambda_functions(lam, run_id_filter=None):
    out = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            name = fn["FunctionName"]
            if not name.startswith(NAME_PREFIX):
                continue
            try:
                tags = lam.list_tags(Resource=fn["FunctionArn"]).get(
                    "Tags", {}
                )
            except ClientError:
                tags = {}
            val = _tag_matches(tags, run_id_filter)
            if val is not None:
                out.append((fn["FunctionArn"], name, val))
    return out


def find_iam_roles(iam, run_id_filter=None):
    out = []
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            name = role["RoleName"]
            if not name.startswith(NAME_PREFIX):
                continue
            try:
                tags = {
                    t["Key"]: t["Value"]
                    for t in iam.list_role_tags(RoleName=name)["Tags"]
                }
            except ClientError:
                tags = {}
            val = _tag_matches(tags, run_id_filter)
            if val is not None:
                out.append((role["Arn"], name, val))
    return out


def find_security_groups(ec2, run_id_filter=None):
    """EC2 supports tag filtering directly — fastest path."""
    if run_id_filter is not None:
        filters = [{"Name": f"tag:{TAG_KEY}", "Values": [run_id_filter]}]
    else:
        filters = [{"Name": "tag-key", "Values": [TAG_KEY]}]
    try:
        resp = ec2.describe_security_groups(Filters=filters)
    except ClientError:
        return []
    out = []
    region = ec2.meta.region_name
    for sg in resp.get("SecurityGroups", []):
        tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
        val = _tag_matches(tags, run_id_filter)
        if val is None:
            continue
        arn = (
            f"arn:aws:ec2:{region}:{sg['OwnerId']}:"
            f"security-group/{sg['GroupId']}"
        )
        out.append((arn, sg["GroupId"], val))
    return out


def find_all(region, run_id_filter=None):
    """Discover every sticky_honey_bun_test_id-tagged resource we know
    how to manage. Returns {service_kind: [(arn, id, tag_value), ...]}."""
    rds = boto3.client("rds", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    return {
        "rds_db":     find_rds_instances(rds, run_id_filter),
        "rds_subgrp": find_rds_subnet_groups(rds, run_id_filter),
        "rds_pg":     find_rds_parameter_groups(rds, run_id_filter),
        "lambda":     find_lambda_functions(lam, run_id_filter),
        "iam_role":   find_iam_roles(iam, run_id_filter),
        "ec2_sg":     find_security_groups(ec2, run_id_filter),
    }
