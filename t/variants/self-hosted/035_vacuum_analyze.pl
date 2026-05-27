# Variants: self-hosted, rds
# (Cross-variant body in t/lib/SHB_Assertions.pm; the RDS twin is
# t/variants/rds/035_vacuum_analyze.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('vacuum_analyze');
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
    INSERT INTO t SELECT g, 'public.t.honey' FROM generate_series(1, 100) g;
});

# Self-hosted count_alerts: read the log file, count lines containing
# the needle. The local logger writes synchronously, so by the time
# the assertion runs, all alerts (if any) are on disk.
my $count_alerts = sub {
    my ($needle) = @_;
    return 0 unless -e $log_path && -s $log_path;
    open my $fh, '<', $log_path or die "open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    return scalar grep { index($_, $needle) >= 0 } @lines;
};

SHB_Assertions::assert_maintenance_ops_silent(
    sub { $node->psql('postgres', $_[0]) },
    $count_alerts,
    'vacuum_analyze_marker_self_hosted',
    'self-hosted ANALYZE/VACUUM silent');

$node->stop;
done_testing();
