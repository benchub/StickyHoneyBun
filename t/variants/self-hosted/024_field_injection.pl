use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;
use JSON::PP;

# The `query` field's JSON-safety is locked down by t/017/021/022. Other
# fields of the alert object also carry user-influenced bytes and must be
# equally well-defanged:
#
#   - `tag`: the stored honey value. Operators pick it, but if an admin
#     delegates planting to a non-fully-trusted role via GRANT USAGE +
#     EXECUTE, the tag they choose is attacker-controlled. If that role
#     is ever compromised, the same applies.
#
#   - `application_name`: any session can `SET application_name = ...` to
#     any bytes it likes (or set PGAPPNAME at process start). Attacker-
#     controlled by definition.
#
#   - `session_user` / `current_user` / `database` / `client_addr` /
#     `pid`: constrained by PG's identifier / address shape; not realistic
#     injection vectors.
#
# This test verifies tag and application_name round-trip JSON-safely and
# cannot hijack the outer alert object's identity-bearing fields.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('field_injection');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

# Plant rows whose tag bytes would corrupt the JSON line if unescaped.
my $tag_inject = '","event":"forged","tag":"x"';
my $tag_multi  = "line1\nline2\n{\"nested\":\"json\"}";

$node->safe_psql('postgres', qq{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, '$tag_inject');
    INSERT INTO t VALUES (2, E'line1\\nline2\\n{"nested":"json"}');
});

# Three triggers: tag-injection row, multi-line-tag row, then a third
# trigger with a JSON-corrupting application_name SET on the session.
my $app_inject = '","event":"forged"';

$node->safe_psql('postgres', 'SELECT * FROM t WHERE id = 1');
$node->safe_psql('postgres', 'SELECT * FROM t WHERE id = 2');
$node->safe_psql('postgres',
    qq{SET application_name = '$app_inject'; SELECT * FROM t WHERE id = 1;});

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, 3,
   'one log line per trap event regardless of tag / app_name content');

my $json = JSON::PP->new;
my @parsed;
for my $i (0 .. $#lines) {
    my $line = $lines[$i];
    chomp $line;
    my $obj = eval { $json->decode($line) };
    ok($obj, sprintf('line %d parses as standalone JSON', $i + 1))
        or diag "decode error: $@\nline: $line";
    push @parsed, $obj if $obj;
}

# Tag round-trip.
is($parsed[0]{tag}, $tag_inject,
   'tag with JSON-corrupting bytes round-trips verbatim');
is($parsed[1]{tag}, $tag_multi,
   'tag with embedded newlines and JSON content round-trips verbatim');

# application_name round-trip on the third event.
is($parsed[2]{application_name}, $app_inject,
   'application_name with JSON-corrupting bytes round-trips verbatim');

# Critical: outer alert object's identity-bearing fields are not hijacked
# by anything in the user-controlled bytes.
for my $i (0 .. $#parsed) {
    is($parsed[$i]{event}, 'read_text',
       sprintf('line %d event is read_text (not forged from any field)', $i + 1));
}

$node->stop;
done_testing();
