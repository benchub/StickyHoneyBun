# Variants: self-hosted, rds
# (Cross-variant body in t/lib/SHB_Assertions.pm; the RDS twin is
# t/variants/rds/036_set_role_detection.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('set_role');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

# Set up: master plants the honey row + grants the planter role
# enough to SELECT. The planter role is the role we'll SET ROLE to.
$node->safe_psql('postgres', q{
    CREATE EXTENSION sticky_honey_bun;
    CREATE TABLE t (id int, honey honey_bun);
    INSERT INTO t VALUES (1, 'public.t.honey.set_role');
    CREATE ROLE planter LOGIN;
    GRANT SELECT ON t TO planter;
});

# Whoami: the master role is whoever the cluster boot uses.
my $master = $node->safe_psql('postgres', 'SELECT current_user');

my $get_event = sub {
    my ($needle) = @_;
    return undef unless -e $log_path && -s $log_path;
    open my $fh, '<', $log_path or die "open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    for my $line (@lines) {
        next unless index($line, $needle) >= 0;
        my $event = eval { decode_json($line) };
        return $@ ? undef : $event;
    }
    return undef;
};

SHB_Assertions::assert_set_role_reflected_in_alert(
    sub { $node->psql('postgres', $_[0]) },
    $get_event,
    tag                   => 'public.t.honey.set_role',
    trigger               => 'SET ROLE planter; SELECT * FROM t',
    expected_session_user => $master,
    expected_current_user => 'planter',
    label                 => 'self-hosted master pivots to planter via SET ROLE');

$node->stop;
done_testing();
