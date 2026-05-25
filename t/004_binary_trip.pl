use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('binary_trip');
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

# COPY ... TO STDOUT BINARY exercises typsend, not typoutput.
$node->safe_psql('postgres', 'COPY t TO STDOUT WITH BINARY');

ok(-e $log_path && -s $log_path, 'log file written via binary protocol read');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my $line = <$fh>;
close $fh;

like($line, qr/"event":"read_binary"/,    'event field is read_binary');
like($line, qr/"tag":"public\.t\.honey"/, 'tag preserved through binary path');

$node->stop;
done_testing();
