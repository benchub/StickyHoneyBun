package SHB_RDS;
#
# SHB_RDS — RDS-test-harness helpers shared across rds/online/t/*.pl.
#
# Each test file under rds/online/t/ runs as its own Perl process under
# `prove`. The outer orchestrator (run.pl) is responsible for setup and
# teardown; once setup finishes, state-<run_id>.json on disk is the
# single source of truth for every test file. Tests read it via
# SHB_RDS::load_state(), get a populated $state hashref, and use the
# helpers below to issue connections, run psql, and poll CloudWatch.
#
# Working directory contract: tests are run from the repo root (that's
# how `prove rds/online/t/*.pl` is invoked from the Makefile target).
# All file paths in this module assume that.

use strict;
use warnings;
use Exporter 'import';
use IPC::Open3 qw(open3);
use Symbol qw(gensym);
use JSON::PP;

our @EXPORT_OK = qw(
    load_state
    connstr
    psql_run
    poll_alert
    run_cmd
    schema_setup
    unique_tag
);

# Where the orchestrator wrote state-<run_id>.json. Tests resolve this
# the same way teardown.py does — relative to the rds/online/ directory.
my $STATE_DIR = 'rds/online';

# run_cmd(\@argv) -> ($rc, $stdout, $stderr)
# Core IPC::Open3 wrapper. Mirrors run.pl's pre-split helper so test
# files don't depend on IPC::Run (not installed by default on Homebrew
# Perl).
sub run_cmd {
    my ($argv) = @_;
    my $err_fh = gensym;
    my $pid = open3(undef, my $out_fh, $err_fh, @$argv);
    my $out = do { local $/; <$out_fh> // '' };
    my $err = do { local $/; <$err_fh> // '' };
    waitpid($pid, 0);
    return ($? >> 8, $out, $err);
}

# load_state([$run_id]) -> $state hashref
# Reads state-<run_id>.json. $run_id defaults to $ENV{SHB_RUN_ID}, which
# the orchestrator exports before invoking `prove`. Dies with a clear
# message if either input is missing — that's a harness bug, not a
# test-time condition we want to recover from.
sub load_state {
    my ($run_id) = @_;
    $run_id //= $ENV{SHB_RUN_ID}
        or die "SHB_RDS::load_state: \$ENV{SHB_RUN_ID} not set "
             . "(was rds/online/run.pl invoked?)\n";
    my $path = "$STATE_DIR/state-$run_id.json";
    open my $fh, '<', $path
        or die "SHB_RDS::load_state: cannot open $path: $!\n";
    my $st = decode_json(do { local $/; <$fh> });
    close $fh;
    return $st;
}

# connstr($state, %overrides) -> URI string
# Default = master role connecting to the postgres db. Overrides:
#   user => 'shbtest_app'
#   password => $state->{app_password}
#   db => 'db_a'
#   search_path => 'shb_t003'  # baked into the URI via options=-csearch_path=...
sub connstr {
    my ($state, %p) = @_;
    my $user = $p{user}     // $state->{master_user};
    my $pw   = $p{password} // $state->{master_password};
    my $db   = $p{db}       // 'postgres';
    my $host = $state->{endpoint}{host};
    my $port = $state->{endpoint}{port};
    my $uri = "postgres://$user:$pw\@$host:$port/$db?sslmode=require";
    if (defined $p{search_path}) {
        # PG accepts startup options via the `options` URI param. -c sets
        # a GUC for the connection's lifetime, so it survives separate
        # psql_run() calls (each of which is a fresh psql process and a
        # fresh PG session, but all share this connstr).
        my $sp = $p{search_path};
        $uri .= "&options=-c%20search_path%3D$sp%2Cpublic";
    }
    return $uri;
}

# psql_run($connstr, $sql) -> ($rc, $stdout, $stderr)
# Runs psql with our standard testing flags: no startup messages, quiet,
# unaligned + tuples-only output (so $stdout is the bare result), and
# fail-fast on any error from the server.
sub psql_run {
    my ($cs, $sql) = @_;
    my ($rc, $out, $err) = run_cmd(
        ['psql', $cs, '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1',
         '-c', $sql]);
    chomp $out;
    return ($rc, $out, $err);
}

# poll_alert($state, $needle, $timeout) -> ($ok, $payload, $stderr)
# Polls the Lambda's CloudWatch log group for an event containing the
# needle string. Returns true if found within $timeout seconds. Default
# is generous: cold-Lambda + CloudWatch ingest can run 30-90s end-to-end
# in practice on db.t4g.micro.
sub poll_alert {
    my ($state, $needle, $timeout) = @_;
    $timeout //= 240;
    my $log_group = $state->{resources}{lambda_log_group};
    my ($rc, $out, $err) = run_cmd(
        ['rds/online/.venv/bin/python3', 'rds/online/poll_alert.py',
         $log_group, $needle, "--timeout=$timeout"]);
    return ($rc == 0, $out, $err);
}

# schema_setup($state, $schema, %connstr_opts) -> $connstr_with_search_path
# Each test file gets its own schema in the shared cluster so tables
# named `t`, `customers`, etc. don't collide across files. The function
# (1) drops the schema CASCADE if it exists (idempotency under
# SHB_REUSE_RUN_ID), (2) creates it fresh, (3) returns a connstr with
# search_path baked in via the `options` URI param.
#
# Typical use:
#
#     my $st = SHB_RDS::load_state();
#     my $cs = SHB_RDS::schema_setup($st, 'shb_t003');
#     SHB_RDS::psql_run($cs, "CREATE TABLE t (id int, honey honey_bun)");
#
# %connstr_opts is passed through to connstr(), so the caller can target
# a non-postgres database or a non-master role for the bootstrap:
#
#     schema_setup($st, 'shb_t801', db => 'db_a');
#
# Cleanup on exit is not registered — schema_setup is idempotent, so the
# next run starts clean regardless of what the previous run left behind.
sub schema_setup {
    my ($state, $schema, %opts) = @_;
    # Use a no-search_path connstr for the bootstrap; otherwise the SET
    # would race against the schema not yet existing.
    my $bootstrap_cs = connstr($state, %opts);
    my ($rc, $out, $err) = psql_run($bootstrap_cs,
        "DROP SCHEMA IF EXISTS $schema CASCADE; CREATE SCHEMA $schema");
    die "SHB_RDS::schema_setup: failed to set up $schema: $err\n"
        if $rc != 0;
    return connstr($state, %opts, search_path => $schema);
}

# unique_tag($state, $label) -> 'shbtest-<run_id>-<label>-<pid><epoch>'
# Builds a CloudWatch-greppable tag distinct from other test runs AND
# from previous invocations of the same test against the same reused
# instance. Without the pid+epoch suffix, SHB_REUSE_RUN_ID reruns
# collide: every text-trip run plants 'shbtest-<run_id>-text_trip',
# poll_alert's 5-minute look-back window returns the oldest match, and
# subsequent runs end up asserting against a stale log line from a
# previous run. The suffix forces every invocation to plant a tag no
# prior run could have produced.
sub unique_tag {
    my ($state, $label) = @_;
    return sprintf("shbtest-%s-%s-%d%d",
        $state->{run_id}, $label, $$, time());
}

1;
