# Variants: self-hosted, rds
# (The "partial index build does not fire the trap" body for the
# canonical honey_bun type lives in t/lib/SHB_Assertions.pm. The
# alias-type and indexed-read coverage below is self-hosted-specific.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

# A partial index on the honey column (e.g. WHERE honey IS NOT NULL) is the
# natural way to make trap-row lookups cheap without indexing the millions of
# legitimate NULL rows. This test verifies:
#   - CREATE INDEX succeeds on honey_bun columns and on aliased-type columns.
#   - Building the index does NOT fire the trap (PG uses typcmp, not typoutput).
#   - Queries that read the trap row through the index still fire the trap.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('partial_index');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    -- Canonical honey_bun column with one trap and many NULL legitimate rows.
    -- Named `t` to match the shared assertion's hard-coded table.
    CREATE TABLE t (id int PRIMARY KEY, honey honey_bun);
    INSERT INTO t
        SELECT g, NULL FROM generate_series(1, 1000) g;
    INSERT INTO t VALUES (1001, 'public.t.honey');

    -- Same shape under an aliased type.
    SELECT create_honey_bun_alias('account_token');
    CREATE TABLE accounts (id int PRIMARY KEY, honey account_token);
    INSERT INTO accounts
        SELECT g, NULL FROM generate_series(1, 1000) g;
    INSERT INTO accounts VALUES (1001, 'public.accounts.honey');
});

sub count_lines {
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my @lines = <$fh>;
    close $fh;
    return scalar @lines;
}

sub clear_log {
    open(my $fh, '>', $log_path) or die "cannot truncate $log_path: $!";
    close $fh;
}

my $run_psql = sub { $node->psql('postgres', $_[0]) };

# $count_alerts counts log lines matching $needle. The shared assertion
# uses it to do a before/after delta around the index build.
my $count_alerts = sub {
    my ($needle) = @_;
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my $n = 0;
    while (my $line = <$fh>) {
        $n++ if index($line, $needle) >= 0;
    }
    close $fh;
    return $n;
};

# ---- canonical honey_bun, via the shared assertion ----

clear_log();
SHB_Assertions::assert_partial_index_build_silent(
    $run_psql, $count_alerts,
    'public.t.honey',
    'partial index build on honey_bun does not fire the trap');

my $hb_idx = $node->safe_psql('postgres', q{
    SELECT 1 FROM pg_indexes
     WHERE schemaname = 'public'
       AND indexname = 'shb_part_idx'
});
is($hb_idx, '1', 'partial index on honey_bun is registered');

# Query that reads the trap value through the indexed path.
clear_log();
my $plan = $node->safe_psql('postgres',
    'EXPLAIN SELECT honey FROM t WHERE honey IS NOT NULL');
like($plan, qr/Index/i,
     'planner chooses the partial index for the trap-row lookup');

clear_log();
$node->safe_psql('postgres',
    'SELECT honey FROM t WHERE honey IS NOT NULL');
is(count_lines(), 1, 'reading the indexed honey value fires the trap once');

# ---- alias type (self-hosted-specific; the shared assertion is hard-
# coded to the canonical `honey_bun` column on table `t`) ----

clear_log();
$node->safe_psql('postgres',
    'CREATE INDEX accounts_honey_idx ON accounts (honey) WHERE honey IS NOT NULL');
is(count_lines(), 0,
   'building a partial index on an alias type does not fire the trap');

my $al_idx = $node->safe_psql('postgres', q{
    SELECT 1 FROM pg_indexes
     WHERE schemaname = 'public'
       AND indexname = 'accounts_honey_idx'
});
is($al_idx, '1', 'partial index on alias type is registered');

clear_log();
$node->safe_psql('postgres', 'ANALYZE accounts');
my $al_plan = $node->safe_psql('postgres',
    'EXPLAIN SELECT honey FROM accounts WHERE honey IS NOT NULL');
like($al_plan, qr/Index/i,
     'planner chooses the partial index on the alias type');

clear_log();
$node->safe_psql('postgres',
    'SELECT honey FROM accounts WHERE honey IS NOT NULL');
is(count_lines(), 1, 'reading the indexed alias value fires the trap once');

$node->stop;
done_testing();
