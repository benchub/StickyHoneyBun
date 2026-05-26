#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: create_honey_bun_alias() produces a type that:
#          (1) registers in pg_type,
#          (2) traps identically (alert fires with correct tag),
#          (3) does NOT fire when the value is NULL (STRICT preserved
#              through the alias indirection),
#          (4) appears in the honey_bun_columns inventory.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t010');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# PG requires "type input functions must exist in the same namespace as
# the type." Our honey_bun_in_rds / honey_bun_out_rds live in `public`,
# so any RDS alias must also live in `public`. We use a per-invocation
# unique name so concurrent runs / reruns don't collide and so a single
# `DROP TYPE` covers cleanup.
my $alias_name = 'shb_alias_' . $$ . '_' . time();
$run->("SELECT create_honey_bun_alias('$alias_name', 'public')");
END {
    SHB_RDS::psql_run(SHB_RDS::connstr($st),
        "DROP TYPE IF EXISTS public.$alias_name CASCADE") if $alias_name;
}

SHB_Assertions::assert_alias_type_registered(
    $run, $alias_name, "$alias_name alias");

# Plant a column of the alias type. INSERT both NULL and non-NULL rows.
my $tag = SHB_RDS::unique_tag($st, 'alias_trip');
my $marker = SHB_RDS::unique_tag($st, 'alias_marker');
$run->("CREATE TABLE accounts (id int, honey public.$alias_name)");
$run->('INSERT INTO accounts VALUES (1, NULL)');
$run->("INSERT INTO accounts VALUES (2, '$tag')");

# Read both — the NULL row must not fire; the non-NULL must.
my ($rc) = $run->("SELECT * FROM accounts /* $marker */");
is($rc, 0, 'SELECT through alias type succeeds');

my $event = $get_event->($tag);
ok($event, 'alias-typed column read fires the trap');
is($event->{tag},   $tag,        'alias alert carries the planted tag')
    if $event;
is($event->{event}, 'read_text', 'alias alert event=read_text')
    if $event;

# Count alerts with the marker — should be exactly 1 (the non-NULL row).
# NULL row must not have invoked the function.
my $count = SHB_RDS::count_alerts($st, $marker, since => 120);
is($count, 1,
    'exactly one alert (non-NULL only) — NULL through alias does not fire');

# Alias appears in the inventory view, just like the canonical type.
SHB_Assertions::assert_inventory_lists_columns(
    $run,
    ['shb_t010.accounts.honey'],
    schema_filter => 'shb_t010',
    label         => 'inventory finds alias-typed column');

done_testing();
