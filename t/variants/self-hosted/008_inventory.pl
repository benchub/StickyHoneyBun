# Variants: self-hosted, rds
# (The inventory-listing and DROP-COLUMN-removal bodies live in
# t/lib/SHB_Assertions.pm and also run against the RDS variant from
# t/variants/rds/008_inventory.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('inventory');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE SCHEMA private;
    CREATE TABLE public.customers (id int, honey honey_bun);
    CREATE TABLE public.audit     (id int, honey honey_bun);
    CREATE TABLE private.sessions (id int, honey honey_bun);
    CREATE TABLE public.no_honey  (id int, name text);
});

my $run_psql = sub { $node->psql('postgres', $_[0]) };

SHB_Assertions::assert_inventory_lists_columns(
    $run_psql,
    [   'private.sessions.honey',
        'public.audit.honey',
        'public.customers.honey',
    ],
    label => 'inventory lists exactly the columns declared as honey_bun');

# Dropping a honey column removes it from the inventory.
SHB_Assertions::assert_dropped_column_removed_from_inventory(
    $run_psql, 'public', 'audit', 'honey',
    'dropped honey column removed from inventory');

$node->stop;
done_testing();
