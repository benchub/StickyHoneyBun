use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

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
    INSERT INTO t VALUES (1, 'public.t.honey');
});

# Each payload trips the trap once (SELECT * FROM t reads the honey value).
# The trailing comment text is what would corrupt the JSON line if unescaped.
# Using ! as the Perl quote delimiter so the payloads' unbalanced {} braces
# don't terminate the quoted string early.
my @payloads = (
    # Line comment: close the JSON object and open a forged one.
    q!SELECT * FROM t -- "}{"event":"forged","tag":"injected"}!,

    # Block comment: backslash + quote + brace sequences.
    q!SELECT * FROM t /* \\ "} "event":"forged" */!,

    # Block comment with an embedded newline. An unescaped newline in the
    # `query` field would split one log line into two, the second of which
    # could parse as a forged event.
    qq!SELECT * FROM t /* "}{\n"event":"forged","tag":"x"} */!,

    # Control characters in the comment: tab, vertical tab, backspace.
    # JSON requires every byte 0x00-0x1F to be escaped.
    qq!SELECT * FROM t -- \t\013\010 "}{"event":"forged"}!,
);

for my $sql (@payloads) {
    $node->safe_psql('postgres', $sql);
}

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

# Exactly one log line per query. Embedded newlines, forged "}{ ..."
# sequences, and stray control characters must not split or multiply output.
is(scalar @lines, scalar @payloads,
   'one log line per triggering query (no forged or split events)');

my $json = JSON::PP->new;
for my $i (0 .. $#lines) {
    my $line = $lines[$i];
    chomp $line;
    my $obj = eval { $json->decode($line) };
    ok($obj, sprintf('log line %d parses as JSON', $i + 1))
        or diag "decode error: $@\nline: $line";
    next unless $obj;

    # Critical: event/tag are the values WE set, not ones the attacker
    # smuggled in via comment text.
    is($obj->{event}, 'read_text',
       sprintf('log line %d event is read_text (not forged)', $i + 1));
    is($obj->{tag}, 'public.t.honey',
       sprintf('log line %d tag is the planted value (not forged)', $i + 1));
}

$node->stop;
done_testing();
