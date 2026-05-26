#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: honey_bun_columns view enumerates planted columns;
#          DROP COLUMN removes the entry. The shared assertion lives
#          in t/lib/SHB_Assertions.pm; the self-hosted twin is
#          t/variants/self-hosted/008_inventory.pl.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t008');
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

# Plant two honey columns under our test schema.
$run->('CREATE TABLE customers (id int, honey honey_bun)');
$run->('CREATE TABLE audit    (id int, honey honey_bun)');

# Inventory should show exactly these two. We filter by schema_name to
# avoid colliding with other tests' schemas in the shared RDS cluster.
SHB_Assertions::assert_inventory_lists_columns(
    $run,
    ['shb_t008.audit.honey', 'shb_t008.customers.honey'],
    schema_filter => 'shb_t008',
    label         => 'inventory lists exactly the planted columns');

SHB_Assertions::assert_dropped_column_removed_from_inventory(
    $run, 'shb_t008', 'audit', 'honey',
    'audit.honey removed from inventory after DROP COLUMN');

done_testing();
