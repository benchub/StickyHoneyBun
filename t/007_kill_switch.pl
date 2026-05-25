use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# sticky_honey_bun.enabled is PGC_POSTMASTER: it can only be set in
# postgresql.conf at server start. ALTER SYSTEM cannot change it at runtime.
# This protects against a compromised superuser session disabling the trap.
# To exercise both the off and on paths, the test stops the node, rewrites
# postgresql.conf, and restarts.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('kill_switch');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
sticky_honey_bun.enabled = off
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

$node->safe_psql('postgres', 'SELECT * FROM t');
ok(! -e $log_path || -z $log_path,
   'enabled=off suppresses log entries on honey reads');

# Attempting to flip the kill switch at runtime should NOT succeed. PGC_POSTMASTER
# means ALTER SYSTEM may write the value but it won't take effect until restart,
# and pg_reload_conf returns a warning we can detect via stderr.
my ($alter_stdout, $alter_stderr, $alter_rc) =
    $node->psql('postgres',
                "ALTER SYSTEM SET sticky_honey_bun.enabled = on; SELECT pg_reload_conf();");
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(! -e $log_path || -z $log_path,
   'pg_reload_conf does not enable the trap mid-run (PGC_POSTMASTER)');

# Stop and restart with enabled=on to confirm the trap CAN be enabled,
# just not at runtime. Append wins over the earlier "off" via last-wins parsing.
$node->stop;
$node->append_conf('postgresql.conf', 'sticky_honey_bun.enabled = on');
$node->start;

$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $log_path && -s $log_path,
   'restart with enabled=on resumes log writes');

$node->stop;
done_testing();
