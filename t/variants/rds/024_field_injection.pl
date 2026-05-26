#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: user-influenced non-query fields (tag from the planted
#          honey value, application_name from the session GUC)
#          round-trip JSON-safely. Embedded newlines, quotes, and
#          forge-shaped bytes in those fields cannot hijack the outer
#          alert object's event field.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t024');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');

# Tag carrying a JSON close-brace + open-brace + forged "event" key.
# If the logger doesn't JSON-escape the tag value, the rest of the
# alert would parse as the forged object.
my $tag_inject_suffix = q{","event":"forged"};
my $tag_inject_base   = SHB_RDS::unique_tag($st, 'tag_inject');
my $tag_inject        = $tag_inject_base . $tag_inject_suffix;
$run->("INSERT INTO t VALUES (1, E'$tag_inject')");

SHB_Assertions::assert_alert_fields(
    $run, $get_event,
    needle  => $tag_inject_base,   # CloudWatch can't match the funky-byte suffix
    tag     => $tag_inject,
    trigger => 'SELECT * FROM t WHERE id = 1',
    label   => 'tag carrying JSON-close-brace + forged event key');

# Tag with embedded newlines + quotes — must be JSON-escaped to `\n`
# without breaking the outer object.
my $tag_multi_suffix = qq{\nforged\n"event":"x"};
my $tag_multi_base   = SHB_RDS::unique_tag($st, 'tag_multi');
my $tag_multi        = $tag_multi_base . $tag_multi_suffix;
$run->("INSERT INTO t VALUES (2, E'$tag_multi')");

SHB_Assertions::assert_alert_fields(
    $run, $get_event,
    needle  => $tag_multi_base,
    tag     => $tag_multi,
    trigger => 'SELECT * FROM t WHERE id = 2',
    label   => 'tag carrying newlines + quotes');

# application_name injection — the GUC is user-settable and contributes
# to the alert payload. Funky bytes there must be JSON-escaped too.
my $app_inject_base = 'shb_inject_';
my $app_inject      = $app_inject_base . q{","event":"forged"};
my $tag_app         = SHB_RDS::unique_tag($st, 'app_inject');
$run->("INSERT INTO t VALUES (3, '$tag_app')");

SHB_Assertions::assert_alert_fields(
    $run, $get_event,
    tag     => $tag_app,
    trigger => "SET application_name = E'$app_inject'; "
             . 'SELECT * FROM t WHERE id = 3',
    expected => { application_name => $app_inject },
    label    => 'application_name carrying JSON-close-brace + forged event');

done_testing();
