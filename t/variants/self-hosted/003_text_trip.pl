# Variants: self-hosted, rds
# (The plant+SELECT+JSON-shape body lives in t/lib/SHB_Assertions.pm and
# also runs against the RDS variant from rds/online/t/003_text_trip.pl.)

use strict;
use warnings;
use lib 't/lib';
use SHB;
use SHB_Assertions;
use JSON::PP;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('text_trip');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);

# Cross-variant assertion wrappers:
#   $run_psql:  $node->psql returns ($rc, $stdout, $stderr) — direct fit.
#   $get_event: tail the log file for a line containing the tag and
#       return the decoded JSON hashref (or undef on miss). The
#       self-hosted logger writes synchronously, so by the time the
#       SELECT in assert_text_trip returns, the alert is already on
#       disk — no polling needed.
my $get_event = sub {
    my ($tag) = @_;
    return undef unless -e $log_path && -s $log_path;
    open my $fh, '<', $log_path or die "cannot open $log_path: $!";
    my @lines = <$fh>;
    close $fh;
    for my $line (@lines) {
        next unless index($line, $tag) >= 0;
        my $event = eval { decode_json($line) };
        return $@ ? undef : $event;
    }
    return undef;
};

SHB_Assertions::assert_text_trip(
    sub { $node->psql('postgres', $_[0]) },
    $get_event,
    'public.t.honey',
    label => 'public.t honey row text-trip (self-hosted)');

$node->stop;
done_testing();
