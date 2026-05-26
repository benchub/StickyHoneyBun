#!/usr/bin/perl
# Variants: rds
# Asserts: the alert payload's `server_addr` field distinguishes which
#          node within a cluster fired the trap. The setup harness
#          provisions a read replica alongside the primary; this test
#          plants on the primary, reads on each node, and verifies
#          that the two alerts carry different `server_addr` values
#          while still agreeing on every other field including
#          `cluster_id` (which is shared across primary + replica
#          because the config table is WAL-replicated).
#
# This is the test 028 (streaming_replica) maps to in the coverage
# matrix — the C variant identifies which node fired via its
# per-cluster log file path; the RDS variant has one Lambda sink, so
# we need an in-payload identifier.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();

plan skip_all => 'no replica_endpoint in state — setup did not provision a replica'
    unless $st->{replica_endpoint} && $st->{replica_endpoint}{host};

my $get_event = SHB_RDS::get_event_fn($st);

# We operate inside db_a because db_a is the database the harness
# populates with an explicit cluster_id (see setup.py). The cluster_id
# is what we want to compare across primary and replica — in the
# postgres db, no cluster_id is configured and `coalesce` falls back
# to inet_server_addr() per-node, which is the very effect server_addr
# exists to capture explicitly. db_a gives us "cluster_id is shared,
# server_addr is not" cleanly.
my $cs_primary = SHB_RDS::schema_setup($st, 'shb_t805', db => 'db_a');

# Replica connection. Same DB, same schema (read-only). We point at
# the replica's endpoint directly. search_path is baked into the URI.
my $cs_replica = sprintf(
    'postgres://%s:%s@%s:%s/db_a?sslmode=require'
  . '&options=-c%%20search_path%%3Dshb_t805%%2Cpublic',
    $st->{master_user},
    $st->{master_password},
    $st->{replica_endpoint}{host},
    $st->{replica_endpoint}{port});

# Plant a honey row on the primary.
SHB_RDS::psql_run($cs_primary,
    'CREATE TABLE t (id int, honey honey_bun)');
my $tag_primary = SHB_RDS::unique_tag($st, 'primary_read');
my $tag_replica = SHB_RDS::unique_tag($st, 'replica_read');
SHB_RDS::psql_run($cs_primary, "INSERT INTO t VALUES (1, '$tag_primary')");
SHB_RDS::psql_run($cs_primary, "INSERT INTO t VALUES (2, '$tag_replica')");

# Wait for the rows to replicate. RDS async replication is typically
# sub-second, but we give it a generous buffer to avoid flake.
sleep 5;

# Fire the trap on each node by reading "its" row. Each invocation
# produces a Lambda event whose server_addr field is the address of
# the node that handled the typeoutput dispatch.
my ($rc_p) = SHB_RDS::psql_run($cs_primary,
    'SELECT * FROM t WHERE id = 1');
is($rc_p, 0, 'SELECT on primary succeeds');

my ($rc_r, $out_r, $err_r) = SHB_RDS::psql_run($cs_replica,
    'SELECT * FROM t WHERE id = 2');
is($rc_r, 0, 'SELECT on replica succeeds')
    or diag("replica SELECT stderr: $err_r");

# Replicas are read-only — sanity check that we connected to one.
my (undef, $is_recovery) = SHB_RDS::psql_run($cs_replica,
    'SELECT pg_is_in_recovery()');
is($is_recovery, 't',
    'replica endpoint actually IS a read-only standby');

# Fetch each event.
my $event_p = $get_event->($tag_primary);
ok($event_p, 'alert arrived for primary read');
my $event_r = $get_event->($tag_replica);
ok($event_r, 'alert arrived for replica read');

# The two alerts must come from different server addresses (the
# load-bearing assertion of this whole test).
if ($event_p && $event_r) {
    isnt($event_p->{server_addr}, $event_r->{server_addr},
        'server_addr differs between primary and replica alerts')
        or diag(
            "  primary server_addr: $event_p->{server_addr}\n"
          . "  replica server_addr: $event_r->{server_addr}");

    # Both fields must be populated (not 'local' — that's the
    # unix-socket fallback and shouldn't appear on RDS).
    isnt($event_p->{server_addr}, 'local',
        'primary alert has a real server_addr (not the unix-socket fallback)');
    isnt($event_r->{server_addr}, 'local',
        'replica alert has a real server_addr');

    # cluster_id is shared (config table is WAL-replicated) — this
    # confirms cluster_id alone could NOT distinguish nodes, which is
    # why server_addr exists.
    is($event_p->{cluster_id}, $event_r->{cluster_id},
        'cluster_id matches across primary + replica (WAL-replicated config)');
}

done_testing();
