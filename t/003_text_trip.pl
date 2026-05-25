use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('text_trip');
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
    INSERT INTO t VALUES (1, 'public.t.honey');
});

$node->safe_psql('postgres', 'SELECT * FROM t');

ok(-e $log_path && -s $log_path, 'log file written via text protocol read');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my $line = <$fh>;
close $fh;

like($line, qr/"event":"read_text"/,        'event field is read_text');
like($line, qr/"tag":"public\.t\.honey"/,   'tag matches planted value');
like($line, qr/"pid":\d+/,                  'pid field present');
like($line, qr/"ts":"\d{4}-\d{2}-\d{2}T/,   'ts is iso-8601-shaped');
like($line, qr/"session_user":"[^"]+"/,     'session_user populated');

$node->stop;
done_testing();
