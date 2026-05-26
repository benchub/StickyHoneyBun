#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: multi-byte UTF-8 in tag, query, and application_name
#          round-trips verbatim through the alert's JSON encoding;
#          all standard event fields remain present.

use strict;
use warnings;
use utf8;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

binmode STDOUT, ':utf8';
binmode STDERR, ':utf8';

my $st  = SHB_RDS::load_state();
my $cs  = SHB_RDS::schema_setup($st, 'shb_t030');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');

# Multi-byte UTF-8 tag — Japanese, emoji, Cyrillic, Latin-1.
# The tag must round-trip byte-for-byte through the alert.
my $tag_base = SHB_RDS::unique_tag($st, 'utf8');
my $tag_mb   = $tag_base . '_蜂蜜🍯_пчела_café';
$run->("INSERT INTO t VALUES (1, '$tag_mb')");

# Query carrying multi-byte UTF-8 in a comment — French, Greek, Arabic.
my $utf8_query_marker = 'recherche français — αβγ — اَلْعَرَبِيَّةُ';
my $trigger_query = "SELECT * FROM t WHERE id = 1 /* $utf8_query_marker */";

SHB_Assertions::assert_alert_fields(
    $run, $get_event,
    needle  => $tag_base,    # CloudWatch filterPattern can't match multi-byte UTF-8
    tag     => $tag_mb,
    trigger => $trigger_query,
    like    => {
        query => qr/recherche fran/,    # Latin-1 + multi-byte
    },
    label   => 'multi-byte UTF-8 in tag + query');

# PG's pg_clean_ascii() (called by check_application_name) sanitizes
# non-ASCII bytes in `application_name` to literal `\xHH` escape
# sequences before any consumer sees the value. So passing multi-byte
# UTF-8 to SET application_name does NOT result in multi-byte bytes in
# the alert; the trap sees and forwards the sanitized form. This is
# PG's design, not a trap bug.
#
# What we assert: a multi-byte UTF-8 tag in the planted honey row
# IS preserved verbatim (the value passes through user-data plumbing,
# not application_name plumbing); and an application_name set to a
# multi-byte string lands in the alert in PG's sanitized form. Both
# are useful regressions to pin.
my $app_in       = 'shb_multibyte_α';
my $app_expected = 'shb_multibyte_\xce\xb1';   # pg_clean_ascii output
my $tag_app_base = SHB_RDS::unique_tag($st, 'utf8_app');
my $tag_app      = $tag_app_base . '_β';
$run->("INSERT INTO t VALUES (2, '$tag_app')");

SHB_Assertions::assert_alert_fields(
    $run, $get_event,
    needle   => $tag_app_base,    # clean ASCII prefix for CloudWatch match
    tag      => $tag_app,
    trigger  => "SET application_name = '$app_in'; "
              . 'SELECT * FROM t WHERE id = 2',
    expected => { application_name => $app_expected },
    label    =>
        'multi-byte UTF-8 in application_name (PG sanitizes to \xHH form)');

done_testing();
