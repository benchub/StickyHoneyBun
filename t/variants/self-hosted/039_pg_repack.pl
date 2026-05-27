# Variants: self-hosted
# (Docker-only: pg_repack is an external tool. The mechanism we're
# checking — that pg_repack's heap rewrite doesn't go through
# typeoutput — is variant-independent, so running the same check on
# RDS wouldn't buy new coverage.)
#
# Asserts: running `pg_repack -t <honey-bearing table>` against a
# table that has a honey_bun column does NOT fire the trap.
# pg_repack rewrites the heap via CREATE TABLE AS + log-table
# replay + catalog swap; none of those paths invoke
# typoutput / typsend. Catches a future pg_repack change (or a
# sticky_honey_bun change that broadens the trap-fire surface) that
# would make routine repacks chatter at the alert processor.
#
# PG 19 NOTE: when the built-in REPACK CONCURRENTLY ships, recheck.
# Its implementation uses logical replication under the covers, and
# logical replication on the publisher DOES fire the trap — see the
# README's "Things to be aware of" section.

use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# pg_repack ships as `postgresql-${PG_MAJOR}-repack` in PGDG. The
# Dockerfile installs it best-effort; if the package isn't available
# for this PG version yet, skip cleanly.
my $pg_config = $ENV{PG_CONFIG} || 'pg_config';
my $bindir = `$pg_config --bindir`;
chomp $bindir;
my $pg_repack = "$bindir/pg_repack";
plan skip_all => "pg_repack not installed at $pg_repack"
    unless -x $pg_repack;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('pg_repack');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', 'CREATE EXTENSION pg_repack');

# Mix of legitimate (NULL) rows + one planted trap. pg_repack needs
# a PK (or NOT NULL unique index) to identify rows during log replay.
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int PRIMARY KEY, honey honey_bun);
    INSERT INTO t SELECT g, NULL FROM generate_series(1, 100) g;
    INSERT INTO t VALUES (1001, 'public.t.honey');
});

sub log_lines {
    return 0 unless -e $log_path;
    open my $fh, '<', $log_path or die "open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    return scalar @lines;
}

# Baseline: confirm the trap is wired. If this fails the rest of
# the test is meaningless.
$node->psql('postgres', 'SELECT honey FROM t WHERE honey IS NOT NULL');
cmp_ok(log_lines(), '>=', 1,
    'baseline: SELECT on a honey row fires the trap');

# Truncate the log and run pg_repack against the honey-bearing table.
open my $clear, '>', $log_path or die "truncate $log_path: $!";
close $clear;

$node->command_ok(
    [$pg_repack, '-h', $node->host, '-p', $node->port,
     '-d', 'postgres', '-t', 'public.t', '--no-superuser-check'],
    'pg_repack succeeds on honey-bearing table');

is(log_lines(), 0,
   'pg_repack produced no alerts (CREATE TABLE AS / log replay / '
 . 'catalog swap path bypasses typeoutput)');

# After repack the table still has the trap row and the trap still
# fires on read. A correctness regression in the repack-vs-trap
# coupling would surface here.
$node->psql('postgres', 'SELECT honey FROM t WHERE honey IS NOT NULL');
cmp_ok(log_lines(), '>=', 1,
    'post-repack: SELECT on the (rewritten) honey row still fires the trap');

$node->stop;
done_testing();
