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
