#!/usr/bin/env python3
"""
setup.py — provision the full AWS stack the RDS online test needs.

USAGE: python3 setup.py <run_id> <preflight.json>

  <run_id>           uniqueness suffix; every resource carries the tag
                     sticky_honey_bun_test_id=<run_id>
  <preflight.json>   path to the JSON blob preflight.py emitted (region,
                     vpc_id, subnet_ids, operator_ip, extra_tags, etc.)

What gets created (in dependency order):

  1. IAM role for Lambda execution + AWSLambdaBasicExecutionRole attach
  2. Lambda function from lambda/handler.py
  3. IAM role for RDS to invoke that Lambda + inline invoke policy
  4. EC2 security group in the operator's VPC, ingress on tcp/5432 from
     operator IP only
  5. RDS DB subnet group spanning the operator's subnets
  6. RDS DB parameter group with rds.allowed_extensions including pg_tle,
     aws_lambda, aws_commons
  7. RDS Postgres instance (db.t4g.micro by default), publicly accessible,
     using the above
  8. Wait for available, then add_role_to_db_instance(FeatureName='Lambda')
     so the instance can invoke our Lambda
  9. Connect as master, install pg_tle + aws_lambda, run
     rds/sticky_honey_bun_rds.sql, CREATE EXTENSION sticky_honey_bun_rds
 10. Create dbs db_a and db_b for the cluster_id multi-db test; install
     the extension in each; ALTER DATABASE … SET cluster_id per db
 11. Create deployer and app roles for the three-role assertion surface
 12. Write rds/online/state-<run_id>.json with everything run.pl needs

State file is written incrementally so a crash mid-flight still leaves
something teardown.py + list_orphans.py can audit.
"""

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
import time
import zipfile
import io

import boto3
from botocore.exceptions import BotoCoreError, ClientError

TAG_KEY = "sticky_honey_bun_test_id"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
LAMBDA_HANDLER = os.path.join(REPO, "lambda", "handler.py")
RDS_SQL = os.path.join(REPO, "rds", "sticky_honey_bun_rds.sql")


def fail(msg, code=1):
    print(f"setup: {msg}", file=sys.stderr)
    sys.exit(code)


def gen_password(n=24):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def tag_list(run_id, extra_tags):
    """Build a list-of-dicts tag spec for AWS APIs that want
    [{'Key':..., 'Value':...}]."""
    tags = [
        {"Key": TAG_KEY, "Value": run_id},
        {
            "Key": "sticky_honey_bun_test_purpose",
            "Value": "automated test - safe to delete",
        },
    ]
    for k, v in (extra_tags or {}).items():
        tags.append({"Key": k, "Value": v})
    return tags


def state_path(run_id):
    return os.path.join(HERE, f"state-{run_id}.json")


def save_state(state):
    """Write atomically so a Ctrl-C mid-write doesn't corrupt the file."""
    path = state_path(state["run_id"])
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def short_id(run_id):
    """First 12 chars of the run_id for AWS resource names (length-bounded)."""
    return run_id.replace("-", "")[:12]


# -------- IAM helpers --------

def create_lambda_execution_role(iam, run_id, extra_tags):
    name = f"shbtest-lambda-exec-{short_id(run_id)}"
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=assume_doc,
        Description="Sticky Honey Bun test - Lambda execution role",
        Tags=tag_list(run_id, extra_tags),
    )
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn=(
            "arn:aws:iam::aws:policy/service-role/"
            "AWSLambdaBasicExecutionRole"
        ),
    )
    # IAM is eventually consistent — wait for the role to be assumable.
    waiter = iam.get_waiter("role_exists")
    waiter.wait(RoleName=name)
    arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    return name, arn


def create_rds_invoke_role(iam, run_id, lambda_arn, extra_tags):
    name = f"shbtest-rds-invoke-{short_id(run_id)}"
    assume_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "rds.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=assume_doc,
        Description="Sticky Honey Bun test - RDS Lambda invoke role",
        Tags=tag_list(run_id, extra_tags),
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="invoke-shbtest-lambda",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": lambda_arn,
            }],
        }),
    )
    waiter = iam.get_waiter("role_exists")
    waiter.wait(RoleName=name)
    arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    return name, arn


# -------- Lambda --------

def zip_lambda_handler():
    if not os.path.exists(LAMBDA_HANDLER):
        fail(f"lambda/handler.py not found at {LAMBDA_HANDLER}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        with open(LAMBDA_HANDLER, "rb") as src:
            zf.writestr("handler.py", src.read())
    return buf.getvalue()


def create_lambda(lam, run_id, role_arn, extra_tags):
    name = f"shbtest-handler-{short_id(run_id)}"
    code_zip = zip_lambda_handler()
    # IAM role propagation lag is real; retry on the assumable-by-Lambda check.
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.11",
                Role=role_arn,
                Handler="handler.lambda_handler",
                Code={"ZipFile": code_zip},
                Timeout=10,
                MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in tag_list(run_id, extra_tags)},
                Description="Sticky Honey Bun test - alert receiver",
            )
            return name, resp["FunctionArn"], f"/aws/lambda/{name}"
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(5)
                continue
            raise
    raise last_err


# -------- EC2 security group --------

def create_security_group(ec2, run_id, vpc_id, operator_ip, extra_tags):
    name = f"shbtest-sg-{short_id(run_id)}"
    resp = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description=f"Sticky Honey Bun test {run_id}",
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": tag_list(run_id, extra_tags),
        }],
    )
    sg_id = resp["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 5432,
            "ToPort": 5432,
            "IpRanges": [{
                "CidrIp": f"{operator_ip}/32",
                "Description": f"Sticky Honey Bun test {run_id} operator",
            }],
        }],
    )
    return sg_id


# -------- RDS --------

def create_db_subnet_group(rds, run_id, subnet_ids, extra_tags):
    name = f"shbtest-subgrp-{short_id(run_id)}"
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription=f"Sticky Honey Bun test {run_id}",
        SubnetIds=subnet_ids,
        Tags=tag_list(run_id, extra_tags),
    )
    return name


def create_db_parameter_group(rds, run_id, extra_tags):
    name = f"shbtest-pg-{short_id(run_id)}"
    # Use the postgres16 family; PG 16 is the engine version we'll request.
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily="postgres16",
        Description=f"Sticky Honey Bun test {run_id}",
        Tags=tag_list(run_id, extra_tags),
    )
    rds.modify_db_parameter_group(
        DBParameterGroupName=name,
        Parameters=[
            {
                "ParameterName": "rds.allowed_extensions",
                "ParameterValue": "pg_tle,aws_lambda,aws_commons",
                "ApplyMethod": "pending-reboot",
            },
            {
                "ParameterName": "shared_preload_libraries",
                "ParameterValue": "pg_tle",
                "ApplyMethod": "pending-reboot",
            },
        ],
    )
    return name


def create_rds_read_replica(rds, run_id, primary_instance, instance_class,
                            sg_id, extra_tags):
    """Provision a read replica of the primary. Used by t/variants/rds/
    805_server_addr.pl to verify that alerts identify which node within
    a cluster fired the trap (primary vs replica)."""
    name = f"shbtest-{short_id(run_id)}-replica"
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=name,
        SourceDBInstanceIdentifier=primary_instance,
        DBInstanceClass=instance_class,
        VpcSecurityGroupIds=[sg_id],
        PubliclyAccessible=True,
        AutoMinorVersionUpgrade=False,
        DeletionProtection=False,
        CopyTagsToSnapshot=False,
        Tags=tag_list(run_id, extra_tags),
    )
    print(f"  waiting for RDS read replica {name} to become available "
          "(another 8-12 minutes) ...")
    waiter = rds.get_waiter("db_instance_available")
    waiter.wait(
        DBInstanceIdentifier=name,
        WaiterConfig={"Delay": 30, "MaxAttempts": 60},
    )
    resp = rds.describe_db_instances(DBInstanceIdentifier=name)
    endpoint = resp["DBInstances"][0]["Endpoint"]
    return name, endpoint["Address"], endpoint["Port"]


def ensure_primary_supports_replicas(rds, primary_instance):
    """RDS rejects CreateDBInstanceReadReplica when the source has
    BackupRetentionPeriod=0. Older harness runs created the primary
    with retention=0; bump it to 1 (the minimum non-zero value) so a
    replica can be provisioned. ApplyImmediately so we don't have to
    wait for the maintenance window.

    The naive `wait_for db_instance_available` is not sufficient here
    because the instance may report `available` before the backup
    settings actually propagate (no state transition for retention
    changes). Poll BackupRetentionPeriod directly until it reflects the
    new value AND the first automated backup has started — that's the
    moment CreateDBInstanceReadReplica will accept the source."""
    resp = rds.describe_db_instances(DBInstanceIdentifier=primary_instance)
    inst = resp["DBInstances"][0]
    if inst.get("BackupRetentionPeriod", 0) > 0:
        return
    print(f"setup: enabling automated backups on {primary_instance} "
          "(required for read-replica creation)")
    rds.modify_db_instance(
        DBInstanceIdentifier=primary_instance,
        BackupRetentionPeriod=1,
        ApplyImmediately=True,
    )
    # Poll: wait for retention to actually reach 1 AND for the
    # instance to be back in `available` (RDS briefly transitions
    # through `backing-up` while the first snapshot kicks off).
    deadline = time.time() + 600  # 10 minutes max
    while time.time() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=primary_instance)
        inst = resp["DBInstances"][0]
        if (inst.get("BackupRetentionPeriod", 0) >= 1
                and inst.get("DBInstanceStatus") == "available"):
            return
        time.sleep(15)
    fail(f"timed out waiting for backups to enable on {primary_instance}")


def ensure_read_replica(rds, run_id, primary_instance, instance_class,
                        sg_id, extra_tags, state):
    """Idempotent replica provisioning. If the replica already exists,
    just refresh the state file with its endpoint. Otherwise provision
    it. Called from both the fresh-setup path and do_install_only so
    that reuse runs against an old instance (provisioned before this
    feature) trigger a one-time replica creation.

    Also attaches the Lambda-invoke IAM role to the replica. The role
    does NOT propagate from the source instance — RDS instance roles
    are per-instance — so without this step, aws_lambda.invoke from a
    replica's PG backend silently fails (the honey_bun_out_rds
    EXCEPTION block swallows the error) and the trap on replica reads
    never reaches CloudWatch."""
    name = f"shbtest-{short_id(run_id)}-replica"
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=name)
        endpoint = resp["DBInstances"][0]["Endpoint"]
        print(f"setup: read replica {name} already exists, reusing")
        host, port = endpoint["Address"], endpoint["Port"]
    except rds.exceptions.DBInstanceNotFoundFault:
        ensure_primary_supports_replicas(rds, primary_instance)
        print(f"setup: creating read replica of {primary_instance}")
        name, host, port = create_rds_read_replica(
            rds, run_id, primary_instance, instance_class,
            sg_id, extra_tags)
    state["resources"]["rds_replica_instance"] = name
    state["replica_endpoint"] = {"host": host, "port": port}
    save_state(state)

    # Attach the Lambda-invoke IAM role. RDS+PostgreSQL only supports
    # ONE ARN per (instance, feature) pair, and re-attaching the same
    # ARN errors with InvalidParameterValue (not the more specific
    # DBInstanceRoleAlreadyExists). Check the current associations
    # before issuing the API call instead of catching after the fact.
    rds_role_arn = state["resources"].get("rds_invoke_role_arn")
    if rds_role_arn:
        resp = rds.describe_db_instances(DBInstanceIdentifier=name)
        existing = resp["DBInstances"][0].get("AssociatedRoles", [])
        already = any(
            r["RoleArn"] == rds_role_arn and r["FeatureName"] == "Lambda"
            for r in existing
        )
        if already:
            print(f"setup: Lambda-invoke role already attached to replica {name}")
        else:
            rds.add_role_to_db_instance(
                DBInstanceIdentifier=name,
                RoleArn=rds_role_arn,
                FeatureName="Lambda",
            )
            print(f"setup: attached Lambda-invoke role to replica {name}")
            time.sleep(10)   # Role attachment takes a few seconds to settle


def create_rds_instance(rds, run_id, instance_class, sg_id, subgrp,
                       paramgrp, master_user, master_pw, extra_tags):
    name = f"shbtest-{short_id(run_id)}"
    rds.create_db_instance(
        DBInstanceIdentifier=name,
        DBInstanceClass=instance_class,
        Engine="postgres",
        EngineVersion="16",
        AllocatedStorage=20,
        StorageType="gp3",
        MasterUsername=master_user,
        MasterUserPassword=master_pw,
        VpcSecurityGroupIds=[sg_id],
        DBSubnetGroupName=subgrp,
        DBParameterGroupName=paramgrp,
        PubliclyAccessible=True,
        # Read replicas require automated backups enabled on the source.
        # 1 day is the minimum non-zero retention; we don't actually
        # rely on the backups for test purposes, but RDS rejects
        # CreateDBInstanceReadReplica without this.
        BackupRetentionPeriod=1,
        MultiAZ=False,
        AutoMinorVersionUpgrade=False,
        DeletionProtection=False,
        CopyTagsToSnapshot=False,
        Tags=tag_list(run_id, extra_tags),
    )
    print(f"  waiting for RDS instance {name} to become available "
          "(this typically takes 8-12 minutes) ...")
    waiter = rds.get_waiter("db_instance_available")
    waiter.wait(
        DBInstanceIdentifier=name,
        WaiterConfig={"Delay": 30, "MaxAttempts": 60},
    )
    resp = rds.describe_db_instances(DBInstanceIdentifier=name)
    endpoint = resp["DBInstances"][0]["Endpoint"]
    return name, endpoint["Address"], endpoint["Port"]


# -------- SQL setup via psql --------

def psql(connstr, sql, dbname=None):
    """Run SQL via psql, capture output, raise on non-zero."""
    cmd = ["psql", connstr, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-At"]
    if dbname:
        cmd += ["-d", dbname]
    cmd += ["-c", sql]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"psql failed (rc={res.returncode}):\n"
            f"  SQL: {sql[:200]}\n"
            f"  stderr: {res.stderr}"
        )
    return res.stdout


def psql_file(connstr, path, dbname=None):
    cmd = ["psql", connstr, "-v", "ON_ERROR_STOP=1", "-X", "-q", "-f", path]
    if dbname:
        cmd += ["-d", dbname]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"psql -f {path} failed (rc={res.returncode}):\n"
            f"  stderr: {res.stderr}"
        )
    return res.stdout


def psql_stdin(connstr, sql_text):
    """Run a SQL blob via psql stdin. Used when we need a single session
    that wraps multiple statements (e.g. SET ROLE + \\i somefile + RESET)."""
    cmd = ["psql", connstr, "-v", "ON_ERROR_STOP=1", "-X", "-q"]
    res = subprocess.run(cmd, input=sql_text, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"psql (stdin) failed (rc={res.returncode}):\n"
            f"  stderr: {res.stderr}"
        )
    return res.stdout


def populate_config(connstr, lambda_arn, cluster_id=None):
    """Write the locked-down config the trap function reads.

    The config table lives in `shb_rds_internal` (NOT public) so that
    blanket `GRANT ... ON ALL TABLES IN SCHEMA public` issued by an
    operator after install does not silently re-grant access to the
    table. The operator (or this setup script) must INSERT the
    lambda_arn and optionally a cluster_id. UPSERT semantics so re-runs
    against the same RDS instance work cleanly."""
    # Single-quote escape: passwords/identifiers we generate are alphanumeric,
    # but lambda ARNs and cluster_ids are operator-supplied — be defensive.
    lambda_arn_esc = lambda_arn.replace("'", "''")
    psql(connstr,
         f"INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config (key, value) "
         f"VALUES ('lambda_arn', '{lambda_arn_esc}') "
         f"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
    if cluster_id:
        cluster_id_esc = cluster_id.replace("'", "''")
        psql(connstr,
             f"INSERT INTO shb_rds_internal.sticky_honey_bun_rds_config (key, value) "
             f"VALUES ('cluster_id', '{cluster_id_esc}') "
             f"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")


def install_extension_stack(connstr, lambda_arn, run_id):
    """Install the full RDS extension chain in the connected database.

    Idempotent: DROPs + pg_tle.uninstall_extension's any previous version
    before reinstalling, so this can be re-run against an existing RDS
    instance after fixing the install SQL (the SHB_REUSE_RUN_ID workflow).

    pg_tle's `install_extension` function requires running as the
    `pgtle_admin` role. The subsequent `CREATE EXTENSION` only requires
    *membership* in pgtle_admin (it gates on can-SET-ROLE-to-pgtle_admin,
    not on currently-being-pgtle_admin). Since pgtle_admin itself lacks
    CREATE on schema `public` in PG 15+, doing `CREATE EXTENSION` while
    SET ROLE'd would fail with `permission denied for schema public`.
    Split: SET ROLE only around the install_extension call, then RESET
    and let the master user (which now has pgtle_admin membership AND
    CREATE on public) do the CREATE EXTENSION."""
    psql(connstr, "CREATE EXTENSION IF NOT EXISTS pg_tle CASCADE")
    psql(connstr, "CREATE EXTENSION IF NOT EXISTS aws_lambda CASCADE")
    psql(connstr, "GRANT pgtle_admin TO CURRENT_USER")

    # Clean out any previous (possibly broken) install. DROP cascades to
    # any tables that reference the type. uninstall_extension removes the
    # source from pg_tle's catalog; wrap in DO/EXCEPTION so it's a no-op
    # when no prior install exists.
    psql(connstr, "DROP EXTENSION IF EXISTS sticky_honey_bun_rds CASCADE")
    psql_stdin(connstr,
        "DO $$ BEGIN\n"
        "    PERFORM pgtle.uninstall_extension('sticky_honey_bun_rds');\n"
        "EXCEPTION WHEN OTHERS THEN NULL;\n"
        "END $$;\n")

    with open(RDS_SQL) as f:
        install_body = f.read()
    psql_stdin(connstr,
        "SET ROLE pgtle_admin;\n"
        + install_body
        + "\nRESET ROLE;\n")

    psql(connstr, "CREATE EXTENSION sticky_honey_bun_rds")


def do_install_only(run_id):
    """Re-run the install + schema steps against the existing RDS instance
    for a previously-set-up run. Used by the SHB_REUSE_RUN_ID iteration
    loop: AWS resources stay up across SQL-fix-and-retry cycles, only the
    extension install + per-db setup + roles are re-run.

    Idempotent throughout: DROPs the extension before reinstalling,
    creates dbs / roles only if missing, GRANTs are inherently idempotent.
    Handles the "first install failed, so db_a / db_b / deployer / app
    don't exist yet" case by completing the remainder of original setup."""
    state_file = state_path(run_id)
    if not os.path.exists(state_file):
        fail(f"no state file at {state_file}; cannot reuse run_id {run_id}")
    with open(state_file) as f:
        state = json.load(f)

    host = state["endpoint"]["host"]
    port = state["endpoint"]["port"]
    master = state["master_user"]
    master_pw = state["master_password"]
    lambda_arn = state["resources"]["lambda_arn"]

    base_connstr = (
        f"postgres://{master}:{master_pw}@{host}:{port}/postgres"
        "?sslmode=require"
    )
    print("setup: reinstalling extension in 'postgres'")
    install_extension_stack(base_connstr, lambda_arn, run_id)
    populate_config(base_connstr, lambda_arn)

    cluster_a = state.get("cluster_id_a") or f"shbtest-{short_id(run_id)}-a"
    cluster_b = state.get("cluster_id_b") or f"shbtest-{short_id(run_id)}-b"
    for db, cluster_id in (("db_a", cluster_a), ("db_b", cluster_b)):
        exists = psql(base_connstr,
            f"SELECT 1 FROM pg_database WHERE datname = '{db}'").strip()
        if not exists:
            print(f"setup: creating database {db}")
            psql(base_connstr, f"CREATE DATABASE {db}")
        db_connstr = base_connstr.replace("/postgres?", f"/{db}?")
        print(f"setup: reinstalling extension in {db}")
        install_extension_stack(db_connstr, lambda_arn, run_id)
        populate_config(db_connstr, lambda_arn, cluster_id)
    state["cluster_id_a"] = cluster_a
    state["cluster_id_b"] = cluster_b
    save_state(state)

    # Roles — may not exist if original setup died before this point.
    deployer_pw = state.get("deployer_password") or gen_password()
    app_pw      = state.get("app_password")      or gen_password()
    for role, pw in (("shbtest_deployer", deployer_pw),
                     ("shbtest_app",      app_pw)):
        exists = psql(base_connstr,
            f"SELECT 1 FROM pg_roles WHERE rolname = '{role}'").strip()
        if not exists:
            print(f"setup: creating role {role}")
            psql(base_connstr,
                 f"CREATE ROLE {role} LOGIN PASSWORD '{pw}'")
    # Deployer grants are idempotent (GRANT on already-granted is no-op).
    psql(base_connstr, "GRANT USAGE ON TYPE honey_bun TO shbtest_deployer")
    psql(base_connstr,
         "GRANT EXECUTE ON FUNCTION honey_bun_in_rds(text) TO shbtest_deployer")
    psql(base_connstr,
         "GRANT EXECUTE ON FUNCTION honey_bun_out_rds(bytea) TO shbtest_deployer")

    state["deployer_user"]     = "shbtest_deployer"
    state["deployer_password"] = deployer_pw
    state["app_user"]          = "shbtest_app"
    state["app_password"]      = app_pw
    save_state(state)

    # Read replica — if this is an existing instance from before
    # ensure_read_replica was introduced, provision it now (one-time
    # ~12-minute step). Subsequent reuse runs find it already there.
    region = state["region"]
    rds = boto3.client("rds", region_name=region)
    primary = state["resources"]["rds_instance"]
    instance_class = state["config"]["instance_class"]
    sg_id = state["resources"]["security_group"]
    extra_tags = state["config"].get("extra_tags", {})
    ensure_read_replica(rds, run_id, primary, instance_class, sg_id,
                        extra_tags, state)

    print(f"setup: reinstall complete for run_id={run_id}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("preflight_json", nargs="?",
                    help="path to preflight.py's JSON output (not needed "
                         "with --install-only)")
    ap.add_argument("--install-only", action="store_true",
                    help="skip AWS provisioning; just (re)install the "
                         "extension on the existing instance for this run_id")
    args = ap.parse_args()
    run_id = args.run_id

    if args.install_only:
        do_install_only(run_id)
        return

    if not args.preflight_json:
        fail("usage: setup.py <run_id> <preflight.json>  "
             "(or --install-only for reinstall on existing instance)")
    with open(args.preflight_json) as f:
        cfg = json.load(f)
    region = cfg["region"]
    vpc_id = cfg["vpc_id"]
    subnet_ids = cfg["subnet_ids"]
    operator_ip = cfg["operator_ip"]
    instance_class = cfg["instance_class"]
    extra_tags = cfg.get("extra_tags", {})

    state = {
        "run_id": run_id,
        "region": region,
        "resources": {},
        "config": cfg,
    }
    save_state(state)

    iam = boto3.client("iam", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    rds = boto3.client("rds", region_name=region)

    print("setup: creating Lambda execution role")
    role_name, role_arn = create_lambda_execution_role(iam, run_id, extra_tags)
    state["resources"]["lambda_exec_role"] = role_name
    save_state(state)

    print("setup: creating Lambda function")
    lambda_name, lambda_arn, lambda_log_group = create_lambda(
        lam, run_id, role_arn, extra_tags
    )
    state["resources"]["lambda_function"] = lambda_name
    state["resources"]["lambda_arn"] = lambda_arn
    state["resources"]["lambda_log_group"] = lambda_log_group
    save_state(state)

    print("setup: creating RDS Lambda-invoke role")
    rds_role_name, rds_role_arn = create_rds_invoke_role(
        iam, run_id, lambda_arn, extra_tags
    )
    state["resources"]["rds_invoke_role"] = rds_role_name
    state["resources"]["rds_invoke_role_arn"] = rds_role_arn
    save_state(state)

    print(f"setup: creating security group in {vpc_id} (ingress from {operator_ip}/32)")
    sg_id = create_security_group(ec2, run_id, vpc_id, operator_ip, extra_tags)
    state["resources"]["security_group"] = sg_id
    save_state(state)

    print(f"setup: creating DB subnet group across {len(subnet_ids)} subnets")
    subgrp = create_db_subnet_group(rds, run_id, subnet_ids, extra_tags)
    state["resources"]["db_subnet_group"] = subgrp
    save_state(state)

    print("setup: creating DB parameter group (pg_tle + aws_lambda)")
    paramgrp = create_db_parameter_group(rds, run_id, extra_tags)
    state["resources"]["db_parameter_group"] = paramgrp
    save_state(state)

    master_user = f"shbtest_master_{short_id(run_id)}"
    master_pw = gen_password()
    state["master_user"] = master_user
    state["master_password"] = master_pw
    save_state(state)

    print(f"setup: creating RDS instance ({instance_class}, postgres 16)")
    instance_id, host, port = create_rds_instance(
        rds, run_id, instance_class, sg_id, subgrp, paramgrp,
        master_user, master_pw, extra_tags,
    )
    state["resources"]["rds_instance"] = instance_id
    state["endpoint"] = {"host": host, "port": port}
    save_state(state)

    print("setup: attaching Lambda-invoke role to RDS instance")
    rds.add_role_to_db_instance(
        DBInstanceIdentifier=instance_id,
        RoleArn=rds_role_arn,
        FeatureName="Lambda",
    )
    # Role attachment takes a few seconds to become effective.
    time.sleep(10)

    base_connstr = (
        f"postgres://{master_user}:{master_pw}@{host}:{port}/postgres"
        "?sslmode=require"
    )

    print("setup: installing pg_tle + aws_lambda + sticky_honey_bun_rds in 'postgres'")
    install_extension_stack(base_connstr, lambda_arn, run_id)
    populate_config(base_connstr, lambda_arn)

    print("setup: creating db_a + db_b for cluster_id multi-db coverage")
    psql(base_connstr, "CREATE DATABASE db_a")
    psql(base_connstr, "CREATE DATABASE db_b")
    cluster_id_a = f"shbtest-{short_id(run_id)}-a"
    cluster_id_b = f"shbtest-{short_id(run_id)}-b"

    db_a_connstr = base_connstr.replace("/postgres?", "/db_a?")
    db_b_connstr = base_connstr.replace("/postgres?", "/db_b?")
    install_extension_stack(db_a_connstr, lambda_arn, run_id)
    populate_config(db_a_connstr, lambda_arn, cluster_id_a)
    install_extension_stack(db_b_connstr, lambda_arn, run_id)
    populate_config(db_b_connstr, lambda_arn, cluster_id_b)

    state["cluster_id_a"] = cluster_id_a
    state["cluster_id_b"] = cluster_id_b
    save_state(state)

    print("setup: creating deployer + app roles")
    deployer_pw = gen_password()
    app_pw = gen_password()
    psql(base_connstr,
         f"CREATE ROLE shbtest_deployer LOGIN PASSWORD '{deployer_pw}'")
    psql(base_connstr,
         f"CREATE ROLE shbtest_app LOGIN PASSWORD '{app_pw}'")
    # deployer gets the trio needed to plant: USAGE on the type, plus
    # EXECUTE on the two I/O functions (the install script REVOKE's both
    # from PUBLIC; without these grants, deployer can't cast to honey_bun).
    # app gets nothing — must fail to plant.
    psql(base_connstr, "GRANT USAGE ON TYPE honey_bun TO shbtest_deployer")
    psql(base_connstr,
         "GRANT EXECUTE ON FUNCTION honey_bun_in_rds(text)  TO shbtest_deployer")
    psql(base_connstr,
         "GRANT EXECUTE ON FUNCTION honey_bun_out_rds(bytea) TO shbtest_deployer")
    state["deployer_user"] = "shbtest_deployer"
    state["deployer_password"] = deployer_pw
    state["app_user"] = "shbtest_app"
    state["app_password"] = app_pw
    save_state(state)

    # Read replica — provisioned after the primary's extension setup is
    # done so 805_server_addr.pl can verify cross-node alert routing.
    ensure_read_replica(rds, run_id, instance_id, instance_class, sg_id,
                        extra_tags, state)

    print(f"\nsetup: complete. State file: {state_path(run_id)}")
    print(f"  endpoint: {host}:{port}")
    print(f"  master:   {master_user}")


if __name__ == "__main__":
    try:
        main()
    except (BotoCoreError, ClientError, RuntimeError, OSError) as e:
        print(f"\nsetup: FATAL: {e}", file=sys.stderr)
        print(
            "\nRun teardown.py with this run_id to clean up partial resources.",
            file=sys.stderr,
        )
        sys.exit(1)
