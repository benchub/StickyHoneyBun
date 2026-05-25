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

1;
