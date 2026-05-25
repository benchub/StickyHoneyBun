use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('null_bypass');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, NULL), (2, NULL);
});

$node->safe_psql('postgres', 'SELECT * FROM t');

ok(! -e $log_path || -z $log_path,
   'no log entries written when only NULL honey values are read');

$node->stop;
done_testing();
