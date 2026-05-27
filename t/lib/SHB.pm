package SHB;
#
# Compatibility shim for PostgreSQL's Perl test modules across major versions.
#
# PG <= 14: PostgresNode + TestLib
# PG >= 15: PostgreSQL::Test::Cluster + PostgreSQL::Test::Utils
#
# Tests do `use lib 't/lib'; use SHB;` and call SHB::new_node(...) /
# SHB::tempdir() instead of referencing either module set directly.

use strict;
use warnings;

our ($CLUSTER, $UTILS);

BEGIN {
    if (eval { require PostgreSQL::Test::Cluster; require PostgreSQL::Test::Utils; 1 }) {
        $CLUSTER = 'PostgreSQL::Test::Cluster';
        $UTILS   = 'PostgreSQL::Test::Utils';
    } elsif (eval { require PostgresNode; require TestLib; 1 }) {
        $CLUSTER = 'PostgresNode';
        $UTILS   = 'TestLib';
    } else {
        die "Neither PostgreSQL::Test::Cluster nor PostgresNode is available";
    }
}

sub new_node { return $CLUSTER->new(@_); }
sub tempdir  { return $UTILS->can('tempdir')->(@_); }

# install_extension($node, %opts) — run CREATE EXTENSION sticky_honey_bun.
#
# Reads $ENV{SHB_INSTALL_SCHEMA} to decide which schema the extension
# installs into. Empty / unset / 'public' = the default install
# (`CREATE EXTENSION sticky_honey_bun`, objects in current_schema()).
# Anything else creates the schema if needed and uses
# `WITH SCHEMA <name>`, then ALTER DATABASE-sets search_path so
# unqualified references to `honey_bun`, `honey_bun_columns`,
# `create_honey_bun_alias` etc. all resolve without rewriting the
# test SQL.
#
# Tests should call this once per cluster instead of issuing
# `CREATE EXTENSION sticky_honey_bun` themselves, so the Makefile's
# `docker-test-matrix` can re-run the full suite under
# SHB_INSTALL_SCHEMA=sticky_honey_bun and catch regressions where a
# code change makes a non-public install fail.
#
# %opts:
#   db => 'postgres'  # database to run CREATE EXTENSION against
sub install_extension {
    my ($node, %opts) = @_;
    my $db = $opts{db} // 'postgres';
    my $schema = $ENV{SHB_INSTALL_SCHEMA} // 'public';
    if ($schema eq '' || $schema eq 'public') {
        $node->safe_psql($db, 'CREATE EXTENSION sticky_honey_bun');
    } else {
        # GRANT USAGE on the schema to PUBLIC: without it, ANY role
        # whose query references the honey_bun type by name (including
        # legitimate readers going through typeoutput dispatch on a
        # planted column) fails at name resolution with "permission
        # denied for schema X". The type's USAGE ACL is the real
        # access-control surface (REVOKEd from PUBLIC by the install
        # body); schema USAGE just lets roles see the names of things
        # they may or may not be allowed to use.
        #
        # search_path: public FIRST, then the install schema. Tests
        # do unqualified CREATE TABLE / CREATE ROLE etc. that should
        # land in public; only TYPE NAMES need to fall through to the
        # install schema. Putting public first keeps test SQL
        # schema-agnostic.
        $node->safe_psql($db,
            "CREATE SCHEMA IF NOT EXISTS $schema; "
          . "CREATE EXTENSION sticky_honey_bun WITH SCHEMA $schema; "
          . "GRANT USAGE ON SCHEMA $schema TO PUBLIC; "
          . "ALTER DATABASE $db SET search_path = public, $schema");
    }
}

# Poll until $cond->() returns truthy or $timeout seconds elapse. Returns
# truthy if the condition was met, false on timeout. Caller decides what to
# do on timeout (typically a cmp_ok / ok with the same condition will then
# fail and report a meaningful diag).
#
# Use instead of bare `sleep N; check_condition` for any test where the
# condition depends on bgworker timing, log-file appends, or other async
# behavior. sleep-based tests flake on slow CI; polling is robust.
sub wait_until {
    my ($cond, $timeout) = @_;
    $timeout //= 10;
    my $deadline = time + $timeout;
    while (time < $deadline) {
        return 1 if $cond->();
        select(undef, undef, undef, 0.1);
    }
    return $cond->();  # one last check at the boundary
}

1;
