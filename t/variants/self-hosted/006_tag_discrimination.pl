use strict;
use warnings;
use lib 't/lib';
use SHB;
use Test::More;

my $log_path = SHB::tempdir() . '/shb.log';

my $node = SHB::new_node('tag_discrimination');
$node->init;
$node->append_conf('postgresql.conf', qq{
shared_preload_libraries = 'sticky_honey_bun'
sticky_honey_bun.log_path = '$log_path'
sticky_honey_bun.heartbeat_interval_seconds = 0
});
$node->start;

SHB::install_extension($node);
$node->safe_psql('postgres', q{
    CREATE TABLE customers (id int, honey honey_bun);
    CREATE TABLE audit     (id int, honey honey_bun);
    INSERT INTO customers VALUES (1, 'public.customers.honey');
    INSERT INTO audit     VALUES (1, 'public.audit.honey');
});

$node->safe_psql('postgres', 'SELECT * FROM customers');
$node->safe_psql('postgres', 'SELECT * FROM audit');

open(my $fh, '<', $log_path) or die "cannot open $log_path: $!";
my @lines = <$fh>;
close $fh;

is(scalar @lines, 2, 'one log line per distinct read');
like($lines[0], qr/customers\.honey/,
     'first reads tag from customers table');
like($lines[1], qr/audit\.honey/,
     'second reads tag from audit table');

$node->stop;
done_testing();
