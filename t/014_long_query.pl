use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

# debug_query_string can be very long (multi-MB EXPLAIN, fat IN-lists,
# embedded blobs). The JSON log line carries it whole, which can exceed
# PIPE_BUF and break POSIX's append-atomicity guarantee. The logger uses
# flock() before writing so concurrent backends serialize cleanly. This
# test verifies the long-query path produces a single well-formed line.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('long_query');
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

# Build a query well past PIPE_BUF (4 KB) by padding with a long comment.
my $padding = '/* ' . ('x' x 16000) . ' */';
my $query   = "SELECT * FROM t WHERE id = 1 $padding";

$node->safe_psql('postgres', $query);

ok(-e $log_path && -s $log_path, 'log file written for long query');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, 1,
   'long-query trap produces exactly one line (no internal split)');

my $line = $lines[0];
chomp $line;

cmp_ok(length($line), '>', 16000,
       'line is genuinely longer than PIPE_BUF');

my $event = eval { decode_json($line) };
ok(!$@, 'long-query log line parses as valid JSON')
    or diag("decode error: $@\nfirst 200 bytes: " . substr($line, 0, 200));

is($event->{tag}, 'public.t.honey',
   'tag field intact past the long-query boundary');

like($event->{query}, qr/xxxxxxxxxxxxxxxxxxxx/,
     'long query content preserved in the query field');

$node->stop;
done_testing();
