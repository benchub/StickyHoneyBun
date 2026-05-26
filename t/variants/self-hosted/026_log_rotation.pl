use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# logrotate's default "create" mode renames the live log out of the way
# and lets the writer recreate the file on its next write. The extension
# uses open(O_CREAT | O_APPEND | O_WRONLY) per event (no long-lived fd),
# so this works naturally — lock it in as a regression guard.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('log_rotation');
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

# Baseline: trap creates the log file.
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $log_path && -s $log_path,
   'initial trap creates the log file');

# Simulate logrotate: rename the file out of place.
my $rotated = "$log_path.1";
rename($log_path, $rotated) or die "cannot rotate: $!";
ok(! -e $log_path && -e $rotated,
   'log rotated out of place');

# Next event: must recreate the live log file at the configured path.
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $log_path && -s $log_path,
   'next trap recreates the log file at the configured path');

# The rotated copy must not be touched by subsequent events.
my $rotated_size_before = -s $rotated;
$node->safe_psql('postgres', 'SELECT * FROM t');
is(-s $rotated, $rotated_size_before,
   'rotated-out log file is not modified by subsequent events');

# Outright deletion works the same way: the next event creates anew.
unlink($log_path) or die "cannot unlink: $!";
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $log_path && -s $log_path,
   'log file is recreated after unlink');

$node->stop;
done_testing();
