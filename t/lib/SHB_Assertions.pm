package SHB_Assertions;
#
# SHB_Assertions — assertion bodies that apply to both the self-hosted
# (C) and RDS (pg_tle) variants.
#
# Each assertion takes a `$run_psql` coderef that the caller wires up.
# The contract for the coderef:
#
#     $run_psql->($sql)  ->  ($rc, $stdout, $stderr)
#
# Self-hosted callers wrap `$node->psql` (PostgreSQL::Test::Cluster).
# RDS callers wrap `SHB_RDS::psql_run($cs, $sql)`.
#
# This module is the home for any check that should produce the same
# expected result against either variant — install presence, ACLs,
# SELECT trip detection, tag-discrimination, etc. Setup logic (cluster
# boot vs RDS provisioning) is variant-specific and stays in its
# respective harness; only the assertion body is shared.

use strict;
use warnings;
use Test::More;

# assert_honey_bun_type_exists($run_psql, $label)
# Both variants register a `honey_bun` base type in the public schema.
# Asserting at the pg_type layer (not pg_extension) gives one check that
# works for both the C extension and the pg_tle TLE wrapper — neither
# variant can ship without this row appearing.
sub assert_honey_bun_type_exists {
    my ($run_psql, $label) = @_;
    $label //= 'honey_bun type exists in pg_type';
    my ($rc, $out) = $run_psql->(
        "SELECT 1 FROM pg_type WHERE typname = 'honey_bun'");
    is($rc,  0,   "$label (query succeeded)");
    is($out, '1', "$label (one row matched)");
}

1;
