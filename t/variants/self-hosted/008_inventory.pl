use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('inventory');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE SCHEMA private;
    CREATE TABLE public.customers (id int, honey honey_bun);
    CREATE TABLE public.audit     (id int, honey honey_bun);
    CREATE TABLE private.sessions (id int, honey honey_bun);
    CREATE TABLE public.no_honey  (id int, name text);
});

my $rows = $node->safe_psql('postgres', q{
    SELECT schema_name || '.' || table_name || '.' || column_name
      FROM honey_bun_columns
});

my @actual = sort split /\n/, $rows;
my @expected = sort (
    'private.sessions.honey',
    'public.audit.honey',
    'public.customers.honey',
);

is_deeply(\@actual, \@expected,
    'inventory lists exactly the columns declared as honey_bun');

# Dropping a honey column removes it from the inventory.
$node->safe_psql('postgres', 'ALTER TABLE public.audit DROP COLUMN honey');

my $after_drop = $node->safe_psql('postgres', q{
    SELECT count(*) FROM honey_bun_columns WHERE table_name = 'audit'
});
is($after_drop, '0', 'dropped honey column removed from inventory');

$node->stop;
done_testing();
