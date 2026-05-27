# Variants: self-hosted
# (Docker-only: the test invokes language runtimes — Python today, more
# languages can be added — that aren't worth installing into the RDS
# variant's test harness. The PG-side behavior we're checking is
# variant-independent: each ORM's "fetch row" idiom must go through
# typeoutput dispatch and therefore fire the trap.)
#
# Asserts: each ORM tester script, when it does the framework's
# natural "read these rows" call, causes honey_bun_out to fire (one
# alert line per planted row read). Catches a future change where an
# ORM-style read path bypasses the trap — e.g., by switching to the
# binary protocol with skipped typsend, by lazy materialization, or
# by some other dispatch shortcut.
#
# Each tester lives at t/orm-testers/<name>.<ext>. The tester:
#   * connects via libpq env vars (PGHOST/PGPORT/PGUSER/PGDATABASE)
#   * reads honey_table via the ORM's idiomatic "fetch all rows" call
#   * prints a short status line to stderr
#   * exits 0 on success
# The driver below sets env vars, spawns each tester, captures
# log-file growth, and asserts the trap fired.

use strict;
use warnings;
use lib 't/lib';
use SHB;
use File::Spec;
use Test::More;

# Each tester carries the language runtime it needs and a `probe`
# command that exits 0 iff the tester's deps are installed. The
# driver skips testers whose probe fails so the file runs cleanly
# in environments where only some language ecosystems are set up
# (e.g., running locally without Ruby).
my @testers = (
    {   name      => 'psycopg2',
        runtime   => ['python3'],
        path      => 't/orm-testers/python_psycopg2.py',
        probe_cmd => ['python3', '-c', 'import psycopg2'],   },
    {   name      => 'sqlalchemy',
        runtime   => ['python3'],
        path      => 't/orm-testers/python_sqlalchemy.py',
        probe_cmd => ['python3', '-c', 'import sqlalchemy'],   },
    {   name      => 'django',
        runtime   => ['python3'],
        path      => 't/orm-testers/python_django.py',
        probe_cmd => ['python3', '-c', 'import django'],   },
    {   name      => 'activerecord',
        runtime   => ['ruby'],
        path      => 't/orm-testers/ruby_activerecord.rb',
        probe_cmd => ['ruby', '-e', "require 'active_record'; require 'pg'"],   },
    {   name      => 'sequelize',
        runtime   => ['node'],
        path      => 't/orm-testers/node_sequelize.js',
        probe_cmd => ['node', '-e', "require('sequelize'); require('pg')"],   },
);

# Filter to testers whose runtime is on PATH AND whose deps import
# cleanly. Run the runtime check (`which`) first because it's fast
# and gives a clearer skip message.
my @available;
for my $t (@testers) {
    my ($runtime) = @{ $t->{runtime} };
    my $found = `which $runtime 2>/dev/null`;
    chomp $found;
    if (!$found) {
        diag("skipping $t->{name}: $runtime not on PATH");
        next;
    }
    # Suppress probe stderr so the test log isn't polluted with
    # ModuleNotFoundError / LoadError on environments missing the lib.
    open my $oldstderr, '>&', \*STDERR or die;
    open STDERR, '>>', File::Spec->devnull or die;
    my $rc = system(@{ $t->{probe_cmd} }) >> 8;
    open STDERR, '>&', $oldstderr or die;
    if ($rc != 0) {
        diag("skipping $t->{name}: probe @{$t->{probe_cmd}} failed");
        next;
    }
    push @available, $t;
}
plan skip_all => 'no ORM testers have their deps installed' unless @available;

# Cluster + extension + a honey-bearing table the testers read from.
my $log_path = SHB::tempdir() . '/shb.log';
my $node = SHB::new_node('orm_reads');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE honey_table (id int PRIMARY KEY, honey honey_bun);
    INSERT INTO honey_table VALUES
      (1, 'public.honey_table.row1'),
      (2, 'public.honey_table.row2'),
      (3, 'public.honey_table.row3');
});

# libpq env for the testers. PostgreSQL::Test::Cluster's $node->host
# is a Unix-socket directory; libpq treats a directory-shaped PGHOST
# as the socket path, so we don't need to add a separate PGSSLMODE
# tweak (Unix sockets bypass SSL).
local $ENV{PGHOST}     = $node->host;
local $ENV{PGPORT}     = $node->port;
local $ENV{PGUSER}     = 'postgres';
local $ENV{PGDATABASE} = 'postgres';
local $ENV{PGPASSWORD} = '';

sub log_size { return 0 unless -e $log_path; return -s $log_path; }

sub tag_count {
    return 0 unless -e $log_path;
    open my $fh, '<', $log_path or die "open $log_path: $!";
    my $n = 0;
    while (my $line = <$fh>) {
        $n++ if $line =~ /"tag":"public\.honey_table\.row/;
    }
    close $fh;
    return $n;
}

for my $tester (@available) {
    my $tags_before = tag_count();
    my $size_before = log_size();

    my ($rc, $out, $err);
    my $errfile = SHB::tempdir() . "/$tester->{name}.err";
    {
        open my $oldstderr, '>&', \*STDERR or die;
        open STDERR, '>', $errfile or die;
        $rc = system(@{ $tester->{runtime} }, $tester->{path}) >> 8;
        open STDERR, '>&', $oldstderr or die;
    }
    my $err_text = do {
        if (-e $errfile) {
            open my $fh, '<', $errfile;
            local $/; <$fh>;
        } else { '' };
    };

    is($rc, 0, "$tester->{name}: tester ran without error")
        or diag("$tester->{name} stderr:\n$err_text");

    my $tags_after = tag_count();
    cmp_ok($tags_after, '>', $tags_before,
        "$tester->{name}: trap fired (log gained "
      . ($tags_after - $tags_before)
      . " honey-tagged alert(s))");
}

$node->stop;
done_testing();
