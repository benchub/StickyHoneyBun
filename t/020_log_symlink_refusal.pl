use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Defense: if the file at sticky_honey_bun.log_path is a symlink, open()
# must refuse to follow it. Otherwise an attacker with shell-level write
# access to the parent directory of the log path can replace the file with
# a symlink to /dev/null (silently suppressing alerts) or to any other file
# the postgres OS user can write (corrupting unrelated state).
#
# Fix: O_NOFOLLOW on the open() call. open() returns -1 with errno=ELOOP,
# and the existing "swallow errors" path drops the event — consistent with
# the rule that broken log paths must not surface as SELECT errors.

my $dir      = SHB::tempdir();
my $log_path = "$dir/shb.log";
my $decoy    = "$dir/decoy";

# Set up the symlink BEFORE PG starts so the very first write encounters it.
open(my $fh, '>', $decoy) or die "cannot create decoy: $!";
close $fh;
symlink($decoy, $log_path) or die "cannot create symlink: $!";

my $node = SHB::new_node('log_symlink_refusal');
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

# Trigger the trap. Today: open() follows the symlink and the decoy gets
# the alert. After fix: open() fails with ELOOP, decoy stays empty.
$node->safe_psql('postgres', 'SELECT * FROM t');

is(-s $decoy, 0,
   'symlinked log path is refused; decoy file is unchanged');
ok(-l $log_path,
   'log path itself remains a symlink (open did not replace it)');

$node->stop;
done_testing();
