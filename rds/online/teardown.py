#!/usr/bin/env python3
"""
teardown.py — delete every AWS resource tagged with a specific
sticky_honey_bun_test_id value.

USAGE: python3 teardown.py <run_id> [--force]

Discovery is tag-based, not state-file-based, so a setup that crashed
mid-creation (and didn't write a complete state file) is still cleanable
— anything tagged sticky_honey_bun_test_id=<run_id> will be found and
removed. Before every destructive API call the resource's tags are
re-fetched and re-verified to bear the expected run_id; a mismatch is
treated as fatal (we refuse to delete it). This is the "only destroy
what we created" paranoia net.

By default the script prints what it found and prompts for confirmation
before deleting. The TAP harness passes --force to skip the prompt
(automated runs can't answer interactive questions).

Dependency order:
  1. RDS instance (waits for deletion to complete)
  2. DB subnet group
  3. DB parameter group
  4. Lambda function
  5. IAM role + its inline / attached policies
  6. EC2 security group
"""

import argparse
import os
import sys
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError

import aws_discovery

TAG_KEY = "sticky_honey_bun_test_id"
HERE = os.path.dirname(os.path.abspath(__file__))


def fail(msg, code=1):
    print(f"teardown: {msg}", file=sys.stderr)
    sys.exit(code)


def state_path(run_id):
    """Mirror of setup.py:state_path. Kept in sync by convention so we
    don't have to import setup.py just to read this constant."""
    return os.path.join(HERE, f"state-{run_id}.json")


def _unlink_state(run_id):
    """Remove the local state file for this run_id, if it exists. Only
    called on clean teardown paths (AWS resources confirmed gone)."""
    path = state_path(run_id)
    try:
        os.unlink(path)
        print(f"teardown: removed local state file {os.path.basename(path)}")
    except FileNotFoundError:
        pass


def discover_resources(region, run_id):
    """Return a dict service → list[(arn, id, tag_value)] for resources
    tagged sticky_honey_bun_test_id=<run_id>. Per-service enumeration,
    no Tagging API required."""
    return aws_discovery.find_all(region, run_id_filter=run_id)


def verify_tag(boto_client, get_tags_fn, identifier, expected_run_id):
    """Re-fetch the resource's tags via the service-specific API and
    verify the run_id matches. Raises if not — we will never delete a
    resource that doesn't bear the expected tag."""
    actual = get_tags_fn(boto_client, identifier)
    if actual.get(TAG_KEY) != expected_run_id:
        raise RuntimeError(
            f"refusing to delete {identifier!r}: tag "
            f"{TAG_KEY}={actual.get(TAG_KEY)!r}, expected {expected_run_id!r}"
        )


# Per-service tag readers — used to re-verify before delete.

def rds_tags(client, arn):
    try:
        resp = client.list_tags_for_resource(ResourceName=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("DBInstanceNotFound",
                                            "DBSubnetGroupNotFoundFault",
                                            "DBParameterGroupNotFound"):
            return {}
        raise
    return {t["Key"]: t["Value"] for t in resp.get("TagList", [])}


def lambda_tags(client, function_arn):
    """Lambda's list_tags wants an ARN, not a bare function name."""
    try:
        resp = client.list_tags(Resource=function_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return {}
        raise
    return resp.get("Tags", {})


def iam_role_tags(client, role_name):
    try:
        resp = client.list_role_tags(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {}
        raise
    return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}


def ec2_sg_tags(client, sg_id):
    try:
        resp = client.describe_security_groups(GroupIds=[sg_id])
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            return {}
        raise
    groups = resp.get("SecurityGroups", [])
    if not groups:
        return {}
    return {t["Key"]: t["Value"] for t in groups[0].get("Tags", [])}


def delete_rds_instance(rds, instance_id, run_id):
    arn = None
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        arn = resp["DBInstances"][0]["DBInstanceArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFound":
            print(f"  RDS {instance_id}: already gone")
            return
        raise
    tags = rds_tags(rds, arn)
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(
            f"refusing to delete RDS instance {instance_id}: tag "
            f"{TAG_KEY}={tags.get(TAG_KEY)!r}, expected {run_id!r}"
        )
    print(f"  deleting RDS instance {instance_id} ...")
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFound":
            return
        raise
    waiter = rds.get_waiter("db_instance_deleted")
    waiter.wait(
        DBInstanceIdentifier=instance_id,
        WaiterConfig={"Delay": 15, "MaxAttempts": 60},  # ~15 min cap
    )
    print(f"  RDS instance {instance_id} deleted")


def delete_db_subnet_group(rds, name, run_id):
    try:
        resp = rds.describe_db_subnet_groups(DBSubnetGroupName=name)
        arn = resp["DBSubnetGroups"][0]["DBSubnetGroupArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBSubnetGroupNotFoundFault":
            print(f"  DB subnet group {name}: already gone")
            return
        raise
    tags = rds_tags(rds, arn)
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(
            f"refusing to delete subnet group {name}: tag mismatch"
        )
    print(f"  deleting DB subnet group {name}")
    rds.delete_db_subnet_group(DBSubnetGroupName=name)


def delete_db_parameter_group(rds, name, run_id):
    try:
        resp = rds.describe_db_parameter_groups(DBParameterGroupName=name)
        arn = resp["DBParameterGroups"][0]["DBParameterGroupArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBParameterGroupNotFound":
            print(f"  DB parameter group {name}: already gone")
            return
        raise
    tags = rds_tags(rds, arn)
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(
            f"refusing to delete parameter group {name}: tag mismatch"
        )
    print(f"  deleting DB parameter group {name}")
    rds.delete_db_parameter_group(DBParameterGroupName=name)


def delete_lambda(lam, arn, name, run_id):
    tags = lambda_tags(lam, arn)
    if not tags:
        print(f"  Lambda {name}: already gone")
        return
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(f"refusing to delete Lambda {name}: tag mismatch")
    print(f"  deleting Lambda {name}")
    lam.delete_function(FunctionName=name)


def delete_iam_role(iam, name, run_id):
    tags = iam_role_tags(iam, name)
    if not tags:
        print(f"  IAM role {name}: already gone")
        return
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(f"refusing to delete IAM role {name}: tag mismatch")
    # Detach managed policies
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    # Delete inline policies
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    # Remove from any instance profiles
    for ip in iam.list_instance_profiles_for_role(RoleName=name)[
        "InstanceProfiles"
    ]:
        iam.remove_role_from_instance_profile(
            InstanceProfileName=ip["InstanceProfileName"], RoleName=name
        )
    print(f"  deleting IAM role {name}")
    iam.delete_role(RoleName=name)


def delete_security_group(ec2, sg_id, run_id):
    tags = ec2_sg_tags(ec2, sg_id)
    if not tags:
        print(f"  security group {sg_id}: already gone")
        return
    if tags.get(TAG_KEY) != run_id:
        raise RuntimeError(f"refusing to delete SG {sg_id}: tag mismatch")
    print(f"  deleting security group {sg_id}")
    # SG deletion can race with RDS ENI release; retry a few times.
    last_err = None
    for _ in range(12):
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "DependencyViolation":
                last_err = e
                time.sleep(10)
                continue
            raise
    raise last_err


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument(
        "--force",
        action="store_true",
        help="skip the interactive confirmation prompt",
    )
    args = ap.parse_args()

    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if not region:
        fail("AWS_REGION must be set")

    found = discover_resources(region, args.run_id)
    flat = []
    for kind, items in found.items():
        for arn, rid, _ in items:
            flat.append((kind, rid, arn))

    if not flat:
        print(f"teardown: no resources found for run_id={args.run_id}")
        _unlink_state(args.run_id)
        return

    print(f"teardown: found {len(flat)} resource(s) tagged "
          f"{TAG_KEY}={args.run_id} in {region}:")
    for kind, rid, arn in flat:
        print(f"  [{kind}] {rid}  ({arn})")

    if not args.force:
        if not sys.stdin.isatty():
            fail(
                "no TTY available for confirmation prompt; "
                "pass --force to skip"
            )
        answer = input("\ndelete all of the above? [yes/NO]: ").strip()
        if answer != "yes":
            fail("aborted by user", code=2)

    # Service clients
    rds = boto3.client("rds", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    # Order matters: RDS instance first (and wait), then subnet group +
    # parameter group, then Lambda + IAM + SG in any order.
    #
    # Within rds_db, replicas must be deleted BEFORE their source primary
    # (RDS rejects delete_db_instance on a primary with live replicas).
    # We sort by inspecting each instance's
    # ReadReplicaSourceDBInstanceIdentifier — replicas have it set, the
    # primary does not.
    errors = []

    rds_dbs = found.get("rds_db", [])
    replicas, primaries = [], []
    for entry in rds_dbs:
        _, instance_id, _ = entry
        try:
            resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
            inst = resp["DBInstances"][0]
            if inst.get("ReadReplicaSourceDBInstanceIdentifier"):
                replicas.append(entry)
            else:
                primaries.append(entry)
        except Exception:
            # If the instance is mid-deletion or unreachable, assume
            # it's a primary so we attempt the delete last (worst case
            # we get a no-op error). Replicas mid-deletion sort the same
            # way; the wait inside delete_rds_instance handles it.
            primaries.append(entry)

    for _, instance_id, _ in replicas + primaries:
        try:
            delete_rds_instance(rds, instance_id, args.run_id)
        except Exception as e:
            errors.append(("rds_db", instance_id, e))

    for _, name, _ in found.get("rds_subgrp", []):
        try:
            delete_db_subnet_group(rds, name, args.run_id)
        except Exception as e:
            errors.append(("rds_subgrp", name, e))

    for _, name, _ in found.get("rds_pg", []):
        try:
            delete_db_parameter_group(rds, name, args.run_id)
        except Exception as e:
            errors.append(("rds_pg", name, e))

    for arn, name, _ in found.get("lambda", []):
        try:
            delete_lambda(lam, arn, name, args.run_id)
        except Exception as e:
            errors.append(("lambda", name, e))

    for _, name, _ in found.get("iam_role", []):
        try:
            delete_iam_role(iam, name, args.run_id)
        except Exception as e:
            errors.append(("iam_role", name, e))

    for _, sg_id, _ in found.get("ec2_sg", []):
        try:
            delete_security_group(ec2, sg_id, args.run_id)
        except Exception as e:
            errors.append(("ec2_sg", sg_id, e))

    if errors:
        print("\nteardown completed with errors:")
        for kind, ident, e in errors:
            print(f"  {kind} {ident}: {e}")
        # State file kept on failure so the operator can re-run teardown
        # against the same run_id without re-reading list_orphans first.
        sys.exit(3)

    _unlink_state(args.run_id)
    print("teardown: all resources removed cleanly")


if __name__ == "__main__":
    main()
