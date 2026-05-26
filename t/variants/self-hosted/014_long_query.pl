# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from t/variants/rds/014_long_query.pl.
# The single-line / log-size invariants below are self-hosted-specific —
# the RDS variant cannot count log lines because alerts go to CloudWatch.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

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

my $tag = 'public.t.honey';

my $get_event = sub {
    my ($needle) = @_;
    return undef unless -e $log_path && -s $log_path;
    open my $fh, '<', $log_path or die "cannot open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    for my $line (@lines) {
        next unless index($line, $needle) >= 0;
        my $event = eval { decode_json($line) };
        return $@ ? undef : $event;
    }
    return undef;
};

SHB_Assertions::assert_alert_fields(
    sub { $node->psql('postgres', $_[0]) },
    $get_event,
    tag     => $tag,
    trigger => $query,
    like    => { query => qr/x{16000}/ },
    label   => 'long query (16 KB padding) produces well-formed alert');

# Self-hosted-specific: the long line must arrive as exactly one log row
# (no internal split from a non-atomic write). This is the property the
# flock() guard exists to protect — the RDS variant can't observe it
# directly because CloudWatch normalizes line framing.
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

$node->stop;
done_testing();
