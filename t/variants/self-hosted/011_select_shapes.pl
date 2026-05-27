use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

# Beyond plain SELECT *, the trap should fire for any query shape that
# materializes a honey_bun value to the client: DISTINCT, MIN/MAX, ORDER BY,
# LIMIT, IN-subselects, GROUP BY, etc. Aggregations like count(col) that do
# not produce the value to the client should NOT fire.

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('select_shapes');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES
        (1, 'public.t.honey'),
        (2, 'public.t.honey'),
        (3, 'public.t.other');
});

sub count_lines {
    return 0 unless -e $log_path;
    open(my $fh, '<', $log_path) or return 0;
    my @lines = <$fh>;
    close $fh;
    return scalar @lines;
}

sub clear_log {
    open(my $fh, '>', $log_path) or die "cannot truncate $log_path: $!";
    close $fh;
}

sub run_or_diag {
    my ($sql) = @_;
    my $out = eval { $node->safe_psql('postgres', $sql) };
    if ($@) {
        diag("query failed: $sql\n$@");
        return undef;
    }
    return $out;
}

# Baseline: SELECT * fires for each row.
clear_log();
$node->safe_psql('postgres', 'SELECT * FROM t');
is(count_lines(), 3, 'SELECT * fires for every row');

# SELECT honey (single column) fires for each row.
clear_log();
$node->safe_psql('postgres', 'SELECT honey FROM t');
is(count_lines(), 3, 'SELECT honey fires for every row');

# WHERE narrows to one materialized row.
clear_log();
$node->safe_psql('postgres', 'SELECT honey FROM t WHERE id = 1');
is(count_lines(), 1, 'SELECT ... WHERE fires only for matched rows');

# LIMIT caps materialization.
clear_log();
$node->safe_psql('postgres', 'SELECT honey FROM t LIMIT 1');
is(count_lines(), 1, 'LIMIT 1 fires once');

# count() does NOT materialize the value, so does not fire.
clear_log();
$node->safe_psql('postgres', 'SELECT count(honey) FROM t');
is(count_lines(), 0, 'count(honey) does not fire (no value sent to client)');

# DISTINCT — collapses duplicates; 2 distinct tags in our data.
clear_log();
my $distinct_out = run_or_diag('SELECT DISTINCT honey FROM t');
ok(defined $distinct_out, 'SELECT DISTINCT honey runs (requires equality op)');
is(count_lines(), 2, 'DISTINCT fires once per unique value materialized');

# MIN — one row materialized.
clear_log();
my $min_out = run_or_diag('SELECT MIN(honey) FROM t');
ok(defined $min_out, 'SELECT MIN(honey) runs (requires ordering)');
is(count_lines(), 1, 'MIN fires once for the materialized aggregate');

# MAX — one row materialized.
clear_log();
my $max_out = run_or_diag('SELECT MAX(honey) FROM t');
ok(defined $max_out, 'SELECT MAX(honey) runs');
is(count_lines(), 1, 'MAX fires once for the materialized aggregate');

# GROUP BY — needs equality.
clear_log();
my $gb_out = run_or_diag('SELECT honey, count(*) FROM t GROUP BY honey');
ok(defined $gb_out, 'SELECT ... GROUP BY honey runs');
is(count_lines(), 2, 'GROUP BY fires once per group');

# ORDER BY honey — needs ordering.
clear_log();
my $ob_out = run_or_diag('SELECT honey FROM t ORDER BY honey');
ok(defined $ob_out, 'SELECT ... ORDER BY honey runs');
is(count_lines(), 3, 'ORDER BY fires once per materialized row');

# Subquery projecting away honey: outer query never materializes it, so
# the trap should not fire.
clear_log();
$node->safe_psql('postgres', 'SELECT count(*) FROM (SELECT honey FROM t) s');
is(count_lines(), 0, 'inner SELECT honey projected away by outer count does not fire');

$node->stop;
done_testing();
