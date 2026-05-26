package SHB_Assertions;
#
# SHB_Assertions — assertion bodies that apply to both the self-hosted
# (C) and RDS (pg_tle) variants.
#
# Each assertion takes coderefs that abstract over the variant-specific
# mechanics. The most common are:
#
#   $run_psql->($sql)  ->  ($rc, $stdout, $stderr)
#       Self-hosted: wrap `$node->psql`.
#       RDS:         wrap `SHB_RDS::psql_run($cs, $sql)`.
#
#   $get_event->($tag) ->  $event_hashref_or_undef
#       Returns the alert JSON, decoded into a Perl hashref. Self-hosted
#       reads the log file and decode_jsons the matching line; RDS uses
#       SHB_RDS::poll_alert + parse_alert_event. undef on miss / parse
#       failure — callers check before dereferencing.
#
#   $count_alerts->($needle, %opts) -> integer
#       For negative-case assertions ("no extra alerts after this op").
#       Self-hosted: count log-file lines containing needle.
#       RDS:         SHB_RDS::count_alerts.
#
# Setup logic (cluster boot vs RDS provisioning) is variant-specific
# and stays out of this module.

use strict;
use warnings;
use Test::More;

# -------- existence + identity --------

# assert_honey_bun_type_exists($run_psql, $label)
# Both variants register a `honey_bun` base type in the public schema.
# Asserting at the pg_type layer (not pg_extension) gives one check
# that works for both the C extension and the pg_tle TLE wrapper —
# neither variant can ship without this row appearing.
sub assert_honey_bun_type_exists {
    my ($run_psql, $label) = @_;
    $label //= 'honey_bun type exists in pg_type';
    my ($rc, $out) = $run_psql->(
        "SELECT 1 FROM pg_type WHERE typname = 'honey_bun'");
    is($rc,  0,   "$label (query succeeded)");
    is($out, '1', "$label (one row matched)");
}

# -------- trap firing --------

# assert_text_trip($run_psql, $get_event, $tag, %opts)
# The textbook trap-trigger: plant a honey row, SELECT it back, then
# verify the generated alert's JSON shape. Both variants produce the
# same alert JSON; the only thing that differs is the transport.
#
# Options:
#   table => 't'              # default; override if `t` is already taken
sub assert_text_trip {
    my ($run_psql, $get_event, $tag, %opts) = @_;
    my $table = $opts{table} // 't';
    my $label = $opts{label} // 'text-protocol read fires the trap';

    my ($rc) = $run_psql->("CREATE TABLE $table (id int, honey honey_bun)");
    is($rc, 0, "$label: CREATE TABLE");

    ($rc) = $run_psql->("INSERT INTO $table VALUES (1, '$tag')");
    is($rc, 0, "$label: INSERT planted honey row");

    ($rc) = $run_psql->("SELECT * FROM $table");
    is($rc, 0, "$label: SELECT succeeds (trap fires async)");

    my $event = $get_event->($tag);
    ok($event, "$label: alert was generated and reachable");
    return unless $event;

    is($event->{event}, 'read_text', "$label: event field is read_text");
    is($event->{tag},   $tag,        "$label: tag matches planted value");
    ok(defined $event->{pid} && $event->{pid} =~ /^\d+$/,
        "$label: pid field is numeric");
    like($event->{ts}, qr/^\d{4}-\d{2}-\d{2}T/,
        "$label: ts is iso-8601-shaped");
    ok(defined $event->{session_user} && length $event->{session_user},
        "$label: session_user populated");
    ok(defined $event->{server_addr} && length $event->{server_addr},
        "$label: server_addr populated (per-node identifier)");
}

# assert_alert_fields($run_psql, $get_event, %opts)
# General-purpose "trigger something, verify the alert's fields match"
# primitive. The workhorse behind 014 / 017 / 021 / 022 / 024 / 030.
#
# Required options:
#   tag      => string         # planted tag (verified verbatim in the
#                              # alert's `tag` field)
#   trigger  => sql            # SQL that fires the trap (typically a SELECT
#                              # of a pre-planted row)
#
# Optional:
#   needle   => string         # what $get_event uses to locate the alert.
#                              # Defaults to $tag, but RDS tests with weird
#                              # bytes in the tag (UTF-8, JSON close-braces,
#                              # control chars) MUST pass a clean ASCII
#                              # prefix here — CloudWatch's filterPattern
#                              # rejects quoted needles with embedded
#                              # special characters.
#   expected => { field => value, ... }  # exact-match field assertions
#   like     => { field => qr/.../, ... }  # regex-match field assertions
#   label    => string         # test-description prefix
#
# Cross-variant invariants (event=read_text, tag matches) are checked
# automatically — only pass the trigger-specific things in `expected`/
# `like`.
sub assert_alert_fields {
    my ($run_psql, $get_event, %opts) = @_;
    my $label    = $opts{label}    // 'alert fields match';
    my $tag      = $opts{tag}      // die "assert_alert_fields: tag required";
    my $needle   = $opts{needle}   // $tag;
    my $trigger  = $opts{trigger}  // die "assert_alert_fields: trigger required";
    my $expected = $opts{expected} // {};
    my $like_re  = $opts{like}     // {};

    my ($rc) = $run_psql->($trigger);
    is($rc, 0, "$label: trigger SQL succeeds");

    my $event = $get_event->($needle);
    ok($event, "$label: alert arrived and parses as JSON");
    return unless $event;

    is($event->{event}, 'read_text', "$label: event=read_text");
    is($event->{tag},   $tag,        "$label: tag matches planted value");
    for my $field (sort keys %$expected) {
        is($event->{$field}, $expected->{$field},
            "$label: $field matches expected");
    }
    for my $field (sort keys %$like_re) {
        like($event->{$field}, $like_re->{$field},
            "$label: $field matches pattern");
    }
}

# -------- ACL / lockdown --------

# assert_io_function_call_denied($run_psql, $sql, $label)
# A non-privileged role calling a honey_bun I/O function by name
# (rather than going through typeoutput dispatch on a stored value)
# must fail with permission denied. The defense is REVOKE EXECUTE
# FROM PUBLIC; the assertion verifies both that the call is rejected
# and that the error message identifies the cause.
sub assert_io_function_call_denied {
    my ($run_psql, $sql, $label) = @_;
    $label //= 'direct I/O function call denied';
    my ($rc, undef, $stderr) = $run_psql->($sql);
    isnt($rc, 0, "$label: call rejected (non-zero rc)");
    like($stderr, qr/permission denied/i,
        "$label: rejected with permission denied");
}

# assert_cast_to_type_denied($run_psql, $type_name, $label)
# A role without USAGE on a honey-shaped type cannot cast to it. The
# error message identifies either the type or its underlying input
# function depending on PG version / dispatch path; the regex accepts
# both shapes.
sub assert_cast_to_type_denied {
    my ($run_psql, $type_name, $label) = @_;
    $label //= "cast to $type_name denied without USAGE";
    my ($rc, undef, $stderr) = $run_psql->("SELECT 'forged'::$type_name");
    isnt($rc, 0, "$label: cast rejected (non-zero rc)");
    like($stderr, qr/permission denied for (type|function)/i,
        "$label: rejected with permission denied for type/function");
}

# assert_create_column_of_type_denied($run_psql, $schema, $type_name, $label)
# Companion to assert_cast_to_type_denied: a role without USAGE also
# cannot create a column of that type. Closes the indirect-forge path
# where an attacker would otherwise CREATE TABLE forge (h honey_bun);
# INSERT ...; SELECT ... to fire alerts with chosen tags.
sub assert_create_column_of_type_denied {
    my ($run_psql, $schema, $type_name, $label) = @_;
    $label //= "create column of $type_name denied without USAGE";
    my ($rc, undef, $stderr) = $run_psql->(
        "CREATE TABLE $schema.forge (h $type_name)");
    isnt($rc, 0, "$label: CREATE TABLE rejected (non-zero rc)");
    like($stderr, qr/permission denied for (type|function)/i,
        "$label: rejected with permission denied for type/function");
}

# -------- inventory view --------

# assert_inventory_lists_columns($run_psql, \@expected, %opts)
# `honey_bun_columns` view (provided by both variants) enumerates every
# planted honey column. @expected is a sorted list of `schema.table.column`
# strings to compare against.
#
# Options:
#   schema_filter => 'shb_t008'   # WHERE schema_name = X (recommended on RDS,
#                                 # where the shared cluster sees rows from
#                                 # all concurrent tests' schemas).
sub assert_inventory_lists_columns {
    my ($run_psql, $expected, %opts) = @_;
    my $label = $opts{label} // 'honey_bun_columns lists planted columns';
    my $schema = $opts{schema_filter};
    my $where = $schema ? "WHERE schema_name = '$schema'" : '';
    my ($rc, $out) = $run_psql->(
        "SELECT schema_name || '.' || table_name || '.' || column_name "
      . "FROM honey_bun_columns $where ORDER BY 1");
    is($rc, 0, "$label: query succeeds");
    my @actual = split /\n/, $out;
    is_deeply(\@actual, $expected, "$label: contents match");
}

# assert_dropped_column_removed_from_inventory($run_psql, $schema, $table,
#                                              $column, $label)
# Verifies that DROP COLUMN removes the entry from honey_bun_columns.
# Test pattern: call after assert_inventory_lists_columns has confirmed
# the column is present.
sub assert_dropped_column_removed_from_inventory {
    my ($run_psql, $schema, $table, $column, $label) = @_;
    $label //= "DROP $schema.$table.$column removes inventory entry";
    my ($rc) = $run_psql->("ALTER TABLE $schema.$table DROP COLUMN $column");
    is($rc, 0, "$label: ALTER TABLE DROP COLUMN succeeds");
    my (undef, $out) = $run_psql->(
        "SELECT count(*) FROM honey_bun_columns "
      . "WHERE schema_name = '$schema' AND table_name = '$table' "
      . "AND column_name = '$column'");
    is($out, '0', "$label: entry removed from honey_bun_columns");
}

# assert_inventory_locked_from_role($run_psql, $label)
# A non-superuser without an explicit GRANT must not be able to SELECT
# from `honey_bun_columns`. This closes the opportunistic-attacker recon
# path: an attacker who landed an app-role session can't enumerate every
# planted trap in one query.
sub assert_inventory_locked_from_role {
    my ($run_psql, $label) = @_;
    $label //= 'honey_bun_columns inventory locked from non-privileged role';
    my ($rc, undef, $stderr) = $run_psql->(
        "SELECT count(*) FROM honey_bun_columns");
    isnt($rc, 0, "$label: SELECT rejected (non-zero rc)");
    like($stderr, qr/permission denied/i,
        "$label: rejected with permission denied");
}

# -------- alias type --------

# assert_alias_type_registered($run_psql, $alias_name, $label)
# After `SELECT create_honey_bun_alias(...)`, the alias must appear in
# pg_type with the expected name. Used by the alias-type tests in
# both variants.
sub assert_alias_type_registered {
    my ($run_psql, $alias_name, $label) = @_;
    $label //= "$alias_name alias type is registered";
    my ($rc, $out) = $run_psql->(
        "SELECT 1 FROM pg_type WHERE typname = '$alias_name'");
    is($rc,  0,   "$label: pg_type query succeeds");
    is($out, '1', "$label: alias appears in pg_type");
}

# -------- partial index --------

# assert_maintenance_ops_silent($run_psql, $count_alerts, $marker, $label)
# ANALYZE and VACUUM on a honey-bearing table must NOT fire the trap.
# They use typcmp / typhash and the storage layer's free-space logic;
# no path through them invokes typeoutput. The caller's $count_alerts
# coderef must be paced — the caller is responsible for waiting until
# Lambda has had time to ingest any in-flight events before invoking
# count.
sub assert_maintenance_ops_silent {
    my ($run_psql, $count_alerts, $marker, $label) = @_;
    $label //= 'ANALYZE/VACUUM do not fire the trap';
    my ($rc) = $run_psql->("/* $marker */ ANALYZE t");
    is($rc, 0, "$label: ANALYZE succeeds");
    ($rc) = $run_psql->("/* $marker */ VACUUM t");
    is($rc, 0, "$label: VACUUM succeeds");
    my $count = $count_alerts->($marker);
    is($count, 0,
        "$label: maintenance ops produced zero alerts "
      . "(typcmp / storage path, not typeoutput)");
}

# assert_set_role_reflected_in_alert($run_psql, $get_event, %opts)
# When a session does SET ROLE before firing the trap, the alert MUST
# carry the original session_user AND the role-switched current_user
# separately. This is the load-bearing property the alert processor relies on
# to detect role-switching shenanigans.
#
# Required:
#   tag                   => string         # planted tag for this read
#   trigger               => sql            # the SQL that fires the trap
#                                           # (e.g. "SET ROLE x; SELECT ...")
#   expected_session_user => string         # immune to SET ROLE
#   expected_current_user => string         # the role after SET ROLE
sub assert_set_role_reflected_in_alert {
    my ($run_psql, $get_event, %opts) = @_;
    my $label    = $opts{label} // 'SET ROLE reflected in alert fields';
    my $tag      = $opts{tag}      // die "tag required";
    my $trigger  = $opts{trigger}  // die "trigger required";
    my $sess     = $opts{expected_session_user} // die "expected_session_user required";
    my $curr     = $opts{expected_current_user} // die "expected_current_user required";

    my ($rc) = $run_psql->($trigger);
    is($rc, 0, "$label: trigger SQL succeeds");

    my $event = $get_event->($tag);
    ok($event, "$label: alert arrived and parses as JSON");
    return unless $event;

    is($event->{session_user}, $sess,
        "$label: session_user = $sess (immune to SET ROLE)");
    is($event->{current_user}, $curr,
        "$label: current_user = $curr (reflects SET ROLE)");
    isnt($event->{session_user}, $event->{current_user},
        "$label: session_user differs from current_user (red flag detector)");
}

# assert_partial_index_build_silent($run_psql, $count_alerts, $needle, $label)
# Building a partial index on a honey_bun column must NOT fire the
# trap — the trap fires on typeoutput, and index builds use typcmp,
# which is a different dispatch path. Critical regression check.
#
# The caller plants honey rows first, then calls this. $count_alerts is
# the variant-specific "how many events match $needle right now"
# coderef. $needle should be the tag prefix that captures only this
# test's alerts (so other concurrent tests don't pollute the count).
sub assert_partial_index_build_silent {
    my ($run_psql, $count_alerts, $needle, $label) = @_;
    $label //= 'partial index build does not fire the trap';
    my $before = $count_alerts->($needle);
    my ($rc) = $run_psql->(
        "CREATE INDEX shb_part_idx ON t (honey) WHERE honey IS NOT NULL");
    is($rc, 0, "$label: CREATE INDEX succeeds");
    ($rc) = $run_psql->("ANALYZE t");
    is($rc, 0, "$label: ANALYZE succeeds");
    my $after = $count_alerts->($needle);
    is($after, $before, "$label: no new alerts produced by index build");
}

1;
