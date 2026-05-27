use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# README claim: "Logical replication subscribers need USAGE on honey_bun.
# The apply worker calls honey_bun_recv to materialize incoming row values;
# the C-level USAGE check fires for the subscription role just like any
# other caller."
#
# t/029 covers the happy path (apply works under a USAGE-bearing owner —
# in that test, superuser). This test covers the negative case: an apply
# worker running as a non-USAGE role MUST stall the subscription, and
# GRANT USAGE MUST recover it. That's the integration test for the same
# pg_type_aclcheck guard that t/023 verifies at the direct-cast level —
# but exercised from the logical-replication apply code path that the
# README documents.
#
# Cross-version reality: PG 14/15 require subscription owners to be
# superusers ("ERROR: permission denied to change owner of subscription;
# the owner of a subscription must be a superuser"). PG 16 introduced
# the pg_create_subscription role + run_as_owner option, which is the
# first version where the apply worker can be made to run as a
# non-superuser. Skip on older versions with the reason recorded — the
# property the README documents simply doesn't exist as a testable
# scenario on PG 14/15 because no non-superuser-owned subscription can
# ever exist there.

my $pub_log = SHB::tempdir() . '/pub.log';
my $sub_log = SHB::tempdir() . '/sub.log';

my $publisher = SHB::new_node('lr_acl_pub');
$publisher->init(allows_streaming => 'logical');
$publisher->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$pub_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$publisher->start;

# PG version gate — done after publisher start so we can SHOW it cheaply.
my $pg_ver = $publisher->safe_psql('postgres', 'SHOW server_version_num') + 0;
if ($pg_ver < 160000) {
    $publisher->stop;
    plan skip_all =>
        'Non-superuser subscription owners require PG 16+ (pg_create_subscription role)';
}

my $subscriber = SHB::new_node('lr_acl_sub');
$subscriber->init;
$subscriber->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$sub_log'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$subscriber->start;

for my $node ($publisher, $subscriber) {
    SHB::install_extension($node);
    $node->safe_psql('postgres', q{
        CREATE TABLE t (id int PRIMARY KEY, honey honey_bun);
    });
}

# Create the non-USAGE subscription owner on the subscriber. REPLICATION
# is needed to be a subscription owner; CREATE on the database is needed
# for ALTER SUBSCRIPTION ... OWNER TO to validate the new owner; USAGE on
# the schema + INSERT on the table let the apply worker write rows once
# USAGE on honey_bun is granted. We deliberately do NOT grant USAGE on
# honey_bun yet.
$subscriber->safe_psql('postgres', q{
    CREATE ROLE sub_role WITH LOGIN REPLICATION;
    GRANT pg_create_subscription TO sub_role;
    GRANT CREATE ON DATABASE postgres TO sub_role;
    GRANT USAGE ON SCHEMA public TO sub_role;
    GRANT ALL ON TABLE t TO sub_role;
});

$publisher->safe_psql('postgres', 'CREATE PUBLICATION p FOR TABLE t');

my $connstr = $publisher->connstr('postgres');
my $connstr_sql = $connstr;
$connstr_sql =~ s/'/''/g;

# Helper that runs SQL and diag-prints the actual error on failure
# (safe_psql's BAIL_OUT gets eaten by the prove harness, producing the
# notorious "exited 29 with no subtests run").
sub diag_psql {
    my ($node, $db, $sql, $label) = @_;
    my ($rc, $stdout, $stderr) = $node->psql($db, $sql);
    if ($rc != 0) {
        diag("$label failed (rc=$rc):");
        diag("  stdout: $stdout") if defined $stdout && $stdout ne '';
        diag("  stderr: $stderr") if defined $stderr && $stderr ne '';
    }
    return ($rc, $stdout, $stderr);
}

# Subscription is created as the cluster superuser (works across PG 14-18).
my ($sub_rc) = diag_psql($subscriber, 'postgres',
    "CREATE SUBSCRIPTION s CONNECTION '$connstr_sql' PUBLICATION p",
    'CREATE SUBSCRIPTION');
is($sub_rc, 0, 'CREATE SUBSCRIPTION succeeds');

# Set both subscription options needed for a non-superuser owner under
# trust-auth connections (PG 16+ test cluster default):
#   - run_as_owner = true: apply uses the owner's identity, not the
#     creator's. Default is false in PG 16, so the apply would otherwise
#     run as the superuser creator and always have USAGE.
#   - password_required = false: non-superuser-owned subscriptions
#     normally require the conninfo to carry a password as a CVE
#     mitigation. Our test cluster uses peer/trust auth on a Unix
#     socket — no password — so we need to opt out. Must be set by a
#     superuser (i.e., now, before the ALTER OWNER below).
my ($r) = diag_psql($subscriber, 'postgres',
    'ALTER SUBSCRIPTION s SET (run_as_owner = true, password_required = false)',
    'SET run_as_owner + password_required');
is($r, 0, 'SET subscription options succeeds');

# Hand the subscription to the non-USAGE role. The apply worker restarts
# and from now on runs with sub_role's privileges.
my ($owner_rc) = diag_psql($subscriber, 'postgres',
    'ALTER SUBSCRIPTION s OWNER TO sub_role',
    'ALTER SUBSCRIPTION OWNER');
is($owner_rc, 0, 'ALTER SUBSCRIPTION OWNER TO sub_role succeeds');

# Insert a honey row on the publisher. The streamed change reaches the
# apply worker, which calls honey_bun_recv → pg_type_aclcheck →
# permission denied. The row MUST NOT arrive on the subscriber.
$publisher->safe_psql('postgres',
    "INSERT INTO t VALUES (1, 'public.t.honey')");

# 3 seconds is well past the apply worker's retry interval; with USAGE
# in place the row would be visible by now.
sleep 3;

is($subscriber->safe_psql('postgres', 'SELECT count(*) FROM t'), '0',
    'row does not replicate while subscription owner lacks USAGE on honey_bun');

# Grant USAGE. After repeated permission-denied errors the apply worker
# may be sleeping on an exponential backoff schedule, so we explicitly
# DISABLE+ENABLE to force a fresh worker process that picks up the new
# privilege immediately. This is what an operator would do in practice
# anyway when recovering a stalled subscription.
$subscriber->safe_psql('postgres',
    'GRANT USAGE ON TYPE honey_bun TO sub_role');
$subscriber->safe_psql('postgres', 'ALTER SUBSCRIPTION s DISABLE');
$subscriber->safe_psql('postgres', 'ALTER SUBSCRIPTION s ENABLE');

SHB::wait_until(sub {
    return $subscriber->safe_psql('postgres', 'SELECT count(*) FROM t') eq '1';
}, 30);
is($subscriber->safe_psql('postgres', 'SELECT count(*) FROM t'), '1',
    'after GRANT USAGE + DISABLE/ENABLE, apply catches up and the honey row materializes');

# Trap on the subscriber side now fires for reads — same trap as t/029
# but reached through the post-recovery apply path.
my $sub_size_before = -e $sub_log ? -s $sub_log : 0;
$subscriber->safe_psql('postgres', 'SELECT * FROM t');
cmp_ok(-e $sub_log ? -s $sub_log : 0, '>', $sub_size_before,
    'subscriber-side read of the recovered row fires the trap');

# Cleanup: drop the subscription before stopping nodes so the publisher's
# slot is released cleanly. Wrap in eval so a stalled subscription doesn't
# kill the test process before done_testing() runs.
eval {
    $subscriber->safe_psql('postgres', 'ALTER SUBSCRIPTION s DISABLE');
    $subscriber->safe_psql('postgres',
        'ALTER SUBSCRIPTION s SET (slot_name = NONE)');
    $subscriber->safe_psql('postgres', 'DROP SUBSCRIPTION s');
};
diag("subscription cleanup error (non-fatal): $@") if $@;

$subscriber->stop;
$publisher->stop;
done_testing();
