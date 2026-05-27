use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('pg_dump_trip');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

# pg_dump streams table data via COPY ... TO STDOUT, which invokes typoutput.
# This confirms the alert processor has something to suppress on by application_name.
$node->command_ok(['pg_dump', '-d', 'postgres'], 'pg_dump succeeds');

ok(-e $log_path && -s $log_path, 'pg_dump produced a log entry');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my $content = do { local $/; <$fh> };
close $fh;

like($content, qr/"tag":"public\.t\.honey"/,
     'honey tag visible in log line emitted during pg_dump');
like($content, qr/"query":"COPY [^"]*"/,
     'logged query shows COPY (pg_dump exfil mechanism)');

$node->stop;
done_testing();
