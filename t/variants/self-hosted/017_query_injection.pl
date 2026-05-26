# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from t/variants/rds/017_query_injection.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

# An attacker controls the SQL text of their queries — including SQL comments,
# which PostgreSQL parses-and-discards but which still appear verbatim in
# debug_query_string and thus in the alert log's `query` field. If those
# bytes were emitted into the JSON line unescaped, the attacker could close
# the object early ("}...) and forge a second event with chosen event/tag
# values. The logger uses PG's escape_json() for every string field, which
# must handle quotes, braces, backslashes, embedded newlines, and the
# control-character range that JSON requires to be \u-escaped.
#
# This test exercises that property end-to-end with payloads specifically
# shaped to forge a second event if any of those bytes leak through unescaped.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('query_injection');
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
});

my $run_psql = sub { $node->psql('postgres', $_[0]) };

# $get_event finds the alert by tag and decode_json's it. Each payload
# gets a unique tag (planted in its own row) so we can match its specific
# event in the log.
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

# Each payload trips the trap once. The trailing comment text is what
# would corrupt the JSON line if unescaped. Using ! as the Perl quote
# delimiter so the payloads' unbalanced {} braces don't terminate the
# quoted string early.
my @payloads = (
    {   label   => 'line-comment closing JSON object + forging another',
        tag     => 'inj_line.public.t.honey',
        comment => q!-- "}{"event":"forged","tag":"injected"}!,
    },
    {   label   => 'block-comment backslash + quote + brace sequences',
        tag     => 'inj_blkesc.public.t.honey',
        comment => q!/* \\ "} "event":"forged" */!,
    },
    {   label   => 'block-comment with embedded newline',
        tag     => 'inj_nl.public.t.honey',
        comment => qq!/* "}{\n"event":"forged","tag":"x"} */!,
    },
    {   label   => 'control characters in line comment',
        tag     => 'inj_ctrl.public.t.honey',
        comment => qq!-- \t\013\010 "}{"event":"forged"}!,
    },
);

my $row_id = 1;
for my $p (@payloads) {
    my $tag = $p->{tag};
    $run_psql->("INSERT INTO t VALUES ($row_id, '$tag')");
    SHB_Assertions::assert_alert_fields(
        $run_psql, $get_event,
        tag     => $tag,
        trigger => "SELECT * FROM t WHERE id = $row_id $p->{comment}",
        label   => "injection: $p->{label}");
    $row_id++;
}

# Self-hosted-specific: the log file must contain exactly one line per
# triggering query — no forged or split events anywhere in the file.
open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, scalar @payloads,
   'one log line per triggering query (no forged or split events)');

$node->stop;
done_testing();
