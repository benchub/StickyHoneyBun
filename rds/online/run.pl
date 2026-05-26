#!/usr/bin/env perl
#
# run.pl — orchestrate the online RDS test.
#
# Flow:
#   1. Skip-all if AWS credentials are not in the environment.
#   2. Generate a fresh run_id and print it BEFORE registering any
#      destructive code, so the operator can manually tear down if even
#      that line crashes for some reason.
#   3. Register an END {} block that always invokes teardown.py --force.
#      No matter what dies below this line, cleanup runs.
#   4. preflight.py — env sanity, IP detection, stale-resource halt.
#   5. setup.py — provision everything; emit state-<run_id>.json.
#   6. Read the state file, run the TAP assertions over a live psql
#      connection + CloudWatch polling for Lambda evidence.
#
# Manual recovery: if this script is interrupted or its END block fails,
# the operator can always run:
#     python3 rds/online/list_orphans.py
#     python3 rds/online/teardown.py <run_id>
# to clean up by hand.

use strict;
use warnings;
use Test::More;
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use File::Temp qw(tempfile);
use JSON::PP;
use Time::HiRes qw(time);

# run_cmd(\@argv) -> ($rc, $stdout, $stderr)
# Replacement for IPC::Run::run; uses core IPC::Open3.
sub run_cmd {
    my ($argv, $stream_stdout) = @_;
    my $err_fh = gensym;
    my $pid = open3(undef, my $out_fh, $err_fh, @$argv);
    my ($out, $err) = ('', '');
    if ($stream_stdout) {
        while (my $line = <$out_fh>) {
            print $line;       # tee to our own stdout
            $out .= $line;
        }
    } else {
        local $/;
        $out = <$out_fh> // '';
    }
    {
        local $/;
        $err = <$err_fh> // '';
    }
    waitpid($pid, 0);
    my $rc = $? >> 8;
    return ($rc, $out, $err);
}

# -------- preconditions --------

my $have_env_auth =
    $ENV{AWS_ACCESS_KEY_ID}
 && $ENV{AWS_SECRET_ACCESS_KEY}
 && $ENV{AWS_SESSION_TOKEN};
my $have_profile = $ENV{AWS_PROFILE};

unless (($have_env_auth || $have_profile)
        && ($ENV{AWS_REGION} || $ENV{AWS_DEFAULT_REGION})
        && $ENV{SHB_TEST_VPC_ID}
        && $ENV{SHB_TEST_SUBNET_IDS}) {
    plan skip_all =>
        "RDS online test requires AWS auth (AWS_PROFILE or "
      . "AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY,SESSION_TOKEN}), "
      . "a region, plus SHB_TEST_VPC_ID and SHB_TEST_SUBNET_IDS";
}

# -------- run_id + always-fire teardown --------

sub gen_run_id {
    my @hex = ('0'..'9', 'a'..'f');
    my $s = '';
    $s .= $hex[int(rand(16))] for 1..16;
    return $s;
}

my $reuse = $ENV{SHB_REUSE_RUN_ID};
my $keep  = $ENV{SHB_KEEP};

my $run_id;
if ($reuse) {
    $run_id = $reuse;
    print STDERR "\nREUSING RUN_ID=$run_id (SHB_REUSE_RUN_ID set; skipping AWS provisioning)\n\n";
} else {
    $run_id = gen_run_id();
    print STDERR "\nRUN_ID=$run_id  (use this with teardown.py if anything fails)\n\n";
}

END {
    return unless $run_id;
    if ($keep) {
        diag("END: SHB_KEEP=1 - leaving AWS resources in place for run_id=$run_id");
        diag("To run more assertions:");
        diag("  SHB_KEEP=1 SHB_REUSE_RUN_ID=$run_id make rds-test-online");
        diag("To tear down when done:");
        diag("  rds/online/.venv/bin/python3 rds/online/teardown.py $run_id");
        return;
    }
    diag("END: invoking teardown for run_id=$run_id");
    my $rc = system('rds/online/.venv/bin/python3', 'rds/online/teardown.py', $run_id, '--force');
    if ($rc != 0) {
        diag("TEARDOWN FAILED for run_id=$run_id");
        diag("Manual recovery:");
        diag("  python3 rds/online/list_orphans.py");
        diag("  python3 rds/online/teardown.py $run_id");
    }
}

# -------- preflight --------

my $setup_rc;
my $setup_err;

if ($reuse) {
    diag("reusing existing RDS instance; reinstalling extension only");
    ($setup_rc, undef, $setup_err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/setup.py',
         $run_id, '--install-only'],
        1,
    );
} else {
    diag("running preflight...");
    my ($pf_rc, $pf_out, $pf_err) =
        run_cmd(['rds/online/.venv/bin/python3', 'rds/online/preflight.py']);
    if ($pf_rc != 0) {
        diag("preflight stderr:\n$pf_err");
        BAIL_OUT("preflight failed");
    }
    my ($pf_fh, $pf_path) = tempfile(SUFFIX => '.json', UNLINK => 1);
    print $pf_fh $pf_out;
    close $pf_fh;

    diag("running setup (this takes 8-12 minutes for RDS provisioning)...");
    ($setup_rc, undef, $setup_err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/setup.py',
         $run_id, $pf_path],
        1,
    );
}

if ($setup_rc != 0) {
    diag("setup stderr:\n$setup_err");
    BAIL_OUT("setup failed");
}

# -------- read state --------

open my $sf, '<', "rds/online/state-$run_id.json"
    or BAIL_OUT("cannot open state file: $!");
my $state = decode_json(do { local $/; <$sf> });
close $sf;

my $host       = $state->{endpoint}{host};
my $port       = $state->{endpoint}{port};
my $master     = $state->{master_user};
my $master_pw  = $state->{master_password};
my $deployer_pw = $state->{deployer_password};
my $app_pw     = $state->{app_password};
my $log_group  = $state->{resources}{lambda_log_group};
my $cluster_a  = $state->{cluster_id_a};
my $cluster_b  = $state->{cluster_id_b};

sub connstr {
    my (%p) = @_;
    my $user = $p{user} // $master;
    my $pw   = $p{password} // $master_pw;
    my $db   = $p{db} // 'postgres';
    return "postgres://$user:$pw\@$host:$port/$db?sslmode=require";
}

sub psql_run {
    my ($cs, $sql) = @_;
    my ($rc, $out, $err) = run_cmd(
        ['psql', $cs, '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1',
         '-c', $sql]);
    chomp $out;
    return ($rc, $out, $err);
}

sub poll_alert {
    my ($needle, $timeout) = @_;
    $timeout //= 60;
    my ($rc, $out, $err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/poll_alert.py',
         $log_group, $needle, "--timeout=$timeout"]);
    return ($rc == 0, $out, $err);
}

# -------- assertions --------

# Connectivity baseline.
{
    my ($rc, $out) = psql_run(connstr(), 'SELECT 1');
    is($rc, 0, 'master can connect and run SELECT 1');
    is($out, '1', 'SELECT 1 returns 1');
}

# Extension is installed in postgres / db_a / db_b.
for my $db (qw(postgres db_a db_b)) {
    my ($rc, $out) = psql_run(
        connstr(db => $db),
        "SELECT count(*) FROM pg_extension WHERE extname = 'sticky_honey_bun_rds'");
    is($out, '1', "sticky_honey_bun_rds extension is installed in $db");
}

# Plant + trigger from postgres db. Use a unique tag so the CloudWatch
# search has a needle that can't collide with other test runs.
my $tag_main = "shbtest-$run_id-main";
{
    # DROP first for SHB_REUSE_RUN_ID idempotency: a previous run's
    # extension reinstall CASCADE-drops the honey_bun column but leaves
    # the table behind with the remaining columns, so a plain CREATE
    # TABLE collides on rerun.
    psql_run(connstr(), "DROP TABLE IF EXISTS t");
    my ($rc) = psql_run(connstr(),
        "CREATE TABLE t (id int, honey honey_bun)");
    is($rc, 0, 'master creates honey-bearing table');
    ($rc) = psql_run(connstr(),
        "INSERT INTO t VALUES (1, '$tag_main')");
    is($rc, 0, 'master plants honey row');
    ($rc) = psql_run(connstr(), 'SELECT * FROM t');
    is($rc, 0, 'master SELECT * FROM t succeeds (trap fires async)');
}

# Lambda CloudWatch evidence — the alert reached the Lambda.
{
    my ($ok, $out, $err) = poll_alert($tag_main, 240);
    ok($ok, "Lambda received the alert for $tag_main")
        or diag("poll_alert stderr: $err");
}

# Cluster-id differentiation — different dbs produce different cluster_id
# values in the Lambda payload.
my $tag_a = "shbtest-$run_id-dba";
my $tag_b = "shbtest-$run_id-dbb";
for my $case ([ 'db_a', $tag_a, $cluster_a ],
              [ 'db_b', $tag_b, $cluster_b ]) {
    my ($db, $tag, $expected_cluster) = @$case;
    my ($rc) = psql_run(connstr(db => $db),
        "DROP TABLE IF EXISTS t; "
      . "CREATE TABLE t (id int, honey honey_bun); "
      . "INSERT INTO t VALUES (1, '$tag'); "
      . "SELECT * FROM t");
    is($rc, 0, "trap fires in $db");

    my ($ok, $payload, $err) = poll_alert($tag, 240);
    ok($ok, "Lambda received the alert from $db")
        or diag("poll_alert stderr: $err");
    if ($ok) {
        like($payload, qr/\Q$expected_cluster\E/,
            "Lambda payload from $db carries cluster_id=$expected_cluster");
    }
}

# Deployer can plant (has explicit USAGE + EXECUTE grants).
{
    my $cs = connstr(user => 'shbtest_deployer', password => $deployer_pw);
    my ($rc, $out, $err) = psql_run(
        $cs, "SELECT 'shbtest-$run_id-deployer'::honey_bun IS NOT NULL");
    is($rc, 0, 'deployer with USAGE+EXECUTE can cast to honey_bun')
        or diag("deployer cast stderr: $err");
}

# App role CANNOT plant (no USAGE, no EXECUTE).
{
    my $cs = connstr(user => 'shbtest_app', password => $app_pw);
    my ($rc, $out, $err) = psql_run(
        $cs, "SELECT 'shbtest-$run_id-app'::honey_bun IS NOT NULL");
    isnt($rc, 0, 'app role cannot cast to honey_bun');
    like($err, qr/permission denied/i,
        'app role cast fails with permission denied');
}

# App role CAN read existing honey-bearing tables — the trap fires for
# any role with SELECT, USAGE is not required to read.
{
    psql_run(connstr(), 'GRANT SELECT ON t TO shbtest_app');
    my $cs = connstr(user => 'shbtest_app', password => $app_pw);
    my $tag_read = "shbtest-$run_id-appread";
    psql_run(connstr(), "INSERT INTO t VALUES (2, '$tag_read')");
    my ($rc) = psql_run($cs, 'SELECT * FROM t');
    is($rc, 0, 'app role can SELECT from existing honey-bearing table');
    my ($ok, $payload, $err) = poll_alert($tag_read, 240);
    ok($ok, 'app-role read fires the trap (no USAGE needed for reads)')
        or diag("poll_alert stderr: $err");
}

# Direct call to honey_bun_out_rds is REVOKEd from PUBLIC.
{
    my $cs = connstr(user => 'shbtest_app', password => $app_pw);
    my ($rc, $out, $err) = psql_run(
        $cs, "SELECT honey_bun_out_rds(convert_to('forged','UTF8'))");
    isnt($rc, 0, 'direct call to honey_bun_out_rds is blocked');
    like($err, qr/permission denied/i,
        'honey_bun_out_rds blocked with permission denied');
}

done_testing();
