use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# sticky_honey_bun.log_path is PGC_POSTMASTER, but resolve_log_path() falls
# back through GetConfigOption("log_directory") on every write. log_directory
# is PGC_SIGHUP — a superuser-level attacker can ALTER SYSTEM SET it and
# pg_reload_conf to redirect every subsequent alert. The fix freezes the
# resolved path at postmaster start so runtime changes to log_directory have
# no effect.

my $dir_a = SHB::tempdir();
my $dir_b = SHB::tempdir();
my $path_a = "$dir_a/sticky_honey_bun.log";
my $path_b = "$dir_b/sticky_honey_bun.log";

# Start with shb_log_path UNSET so resolve_log_path falls through to
# log_directory. This is the bypass surface.
my $node = SHB::new_node('log_path_frozen');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
log_directory = '$dir_a'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey');
});

# Baseline: trap writes to the log_directory-derived path resolved at
# postmaster start.
$node->safe_psql('postgres', 'SELECT * FROM t');
ok(-e $path_a && -s $path_a,
   'initial trap logs to the postmaster-time-resolved path');

# Simulate the compromised-superuser bypass: change log_directory at runtime.
# Today this is honored on the next write (resolve_log_path re-queries the
# GUC each call). After fix: the change is ignored, path stays at $path_a.
$node->safe_psql('postgres', "ALTER SYSTEM SET log_directory = '$dir_b'");
$node->safe_psql('postgres', 'SELECT pg_reload_conf()');

my $size_a_before = -s $path_a;
$node->safe_psql('postgres', 'SELECT * FROM t');

cmp_ok(-s $path_a, '>', $size_a_before,
    'after runtime log_directory change, alerts still land in the original path');
ok(! -e $path_b || -z $path_b,
    'runtime log_directory change does not divert alerts to the new path');

$node->stop;
done_testing();
