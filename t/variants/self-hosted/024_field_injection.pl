# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from t/variants/rds/024_field_injection.pl.
# The exact byte-for-byte round-trip checks below are self-hosted-specific.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

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
# Each row uses a unique recognizable prefix so $get_event can find it
# by needle even when the suffix bytes are funky.
my $tag_inject_base = 'shb_inject_field_tag1';
my $tag_inject      = $tag_inject_base . '","event":"forged","tag":"x"';

my $tag_multi_base = 'shb_inject_field_tag2';
my $tag_multi      = $tag_multi_base . qq{\nforged\n{"nested":"json"}};

my $tag_app = 'shb_inject_field_appname.public.t.honey';

$node->safe_psql('postgres', qq{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, '$tag_inject');
    INSERT INTO t VALUES (2, E'${tag_multi_base}\\nforged\\n{"nested":"json"}');
    INSERT INTO t VALUES (3, '$tag_app');
});

my $run_psql = sub { $node->psql('postgres', $_[0]) };

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

# Tag carrying JSON-close-brace + forged event key.
SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    needle  => $tag_inject_base,    # funky suffix bytes need a clean needle
    tag     => $tag_inject,
    trigger => 'SELECT * FROM t WHERE id = 1',
    label   => 'tag carrying JSON-close-brace + forged event key');

# Tag with embedded newlines + JSON content.
SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    needle  => $tag_multi_base,
    tag     => $tag_multi,
    trigger => 'SELECT * FROM t WHERE id = 2',
    label   => 'tag carrying newlines + JSON content');

# application_name injection — the GUC is user-settable and contributes
# to the alert payload. Funky bytes there must be JSON-escaped too.
my $app_inject = '","event":"forged"';
SHB_Assertions::assert_alert_fields(
    $run_psql, $get_event,
    tag      => $tag_app,
    trigger  => qq{SET application_name = '$app_inject'; SELECT * FROM t WHERE id = 3;},
    expected => { application_name => $app_inject },
    label    => 'application_name carrying JSON-close-brace + forged event');

# Self-hosted-specific: exactly N log lines for N triggers (no forged or
# split events anywhere in the file).
open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, 3,
   'one log line per trap event regardless of tag / app_name content');

$node->stop;
done_testing();
