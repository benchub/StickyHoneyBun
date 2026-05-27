use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# When the alert path is inaccessible — chmod 000 on the parent directory,
# disk full, EACCES on the file — open() returns -1 and do_log_event must
# return silently. Surfacing the error as a SELECT failure would unmask
# the trap to the attacker. The trade-off is silent alert loss, which the
# heartbeat deadman is designed to detect.
#
# This test verifies:
#   (a) a trap query whose log write fails does NOT error to the client
#       (no trap unmask);
#   (b) the query's rows are returned normally (the SELECT completes);
#   (c) once the path becomes writable again, alerts resume.

my $dir      = SHB::tempdir();
my $log_path = "$dir/shb.log";

# Ensure the tempdir is readable again on EVERY exit path. If an assertion
# below die's between the chmod-0 and chmod-0755, the harness's tempdir
# cleanup would otherwise hit a directory it cannot enter.
END {
    chmod 0755, $dir if defined $dir && -e $dir;
}

my $node = SHB::new_node('log_permission_denied');
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

# Make the log file's parent directory unwriteable. open(O_CREAT) requires
# write+exec on the parent; with mode 0000 both are denied → EACCES.
chmod 0, $dir or die "cannot chmod $dir: $!";

# Trigger the trap. SELECT must succeed and return its row even though
# the log write is impossible. The internal error is caught by the
# subtransaction wrapper and FlushErrorState'd; the SELECT continues.
my ($rc, $stdout, $stderr) = $node->psql('postgres', 'SELECT * FROM t');
is($rc, 0,
   'trap query succeeds with unwriteable log path (no unmask)');
like($stdout, qr/1\|public\.t\.honey/,
   'trap query returns its rows normally');
unlike($stderr, qr/sticky.honey.bun|honey_bun/i,
   'no extension-named error leaks to the client');

# No log file was created (open failed before creation).
ok(! -e $log_path,
   'no log file created when parent dir is unwriteable');

# Restore permissions and confirm the trap resumes logging cleanly.
chmod 0755, $dir or die "cannot restore $dir perms: $!";
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $log_path && -s $log_path,
   'after parent dir becomes writable, alerts resume');

$node->stop;
done_testing();
