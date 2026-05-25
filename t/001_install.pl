use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('install');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
});
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION sticky_honey_bun');

my $type_exists = $node->safe_psql('postgres',
    "SELECT 1 FROM pg_type WHERE typname = 'honey_bun'");
is($type_exists, '1', 'honey_bun type registered after CREATE EXTENSION');

my $log_path_setting = $node->safe_psql('postgres',
    'SHOW sticky_honey_bun.log_path');
is($log_path_setting, $log_path, 'sticky_honey_bun.log_path GUC honored');

$node->stop;
done_testing();
