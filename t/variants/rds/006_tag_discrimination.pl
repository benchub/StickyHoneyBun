#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: distinct planted tags produce distinct alerts. Each SELECT
#          that materializes a honey row emits one Lambda invocation
#          carrying that row's tag verbatim — multiple tables with
#          different tags don't cross-contaminate.

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;

my $st = SHB_RDS::load_state();
my $cs = SHB_RDS::schema_setup($st, 'shb_t006');
my $get_event = SHB_RDS::get_event_fn($st);

my $tag_customers = SHB_RDS::unique_tag($st, 'customers');
my $tag_audit     = SHB_RDS::unique_tag($st, 'audit');

# Plant two tables, each with its own honey tag.
SHB_RDS::psql_run($cs, 'CREATE TABLE customers (id int, honey honey_bun)');
SHB_RDS::psql_run($cs, 'CREATE TABLE audit    (id int, honey honey_bun)');
SHB_RDS::psql_run($cs, "INSERT INTO customers VALUES (1, '$tag_customers')");
SHB_RDS::psql_run($cs, "INSERT INTO audit     VALUES (1, '$tag_audit')");

# Read both — order-independent, each SELECT fires its own alert.
my ($rc1) = SHB_RDS::psql_run($cs, 'SELECT * FROM customers');
is($rc1, 0, 'SELECT customers succeeds');
my ($rc2) = SHB_RDS::psql_run($cs, 'SELECT * FROM audit');
is($rc2, 0, 'SELECT audit succeeds');

# Each tag should produce exactly its own alert with the correct tag
# field — the two reads do not contaminate each other's payloads.
my $event_customers = $get_event->($tag_customers);
ok($event_customers, "alert arrived for $tag_customers");
is($event_customers->{tag}, $tag_customers,
    'customers alert carries customers tag')
    if $event_customers;

my $event_audit = $get_event->($tag_audit);
ok($event_audit, "alert arrived for $tag_audit");
is($event_audit->{tag}, $tag_audit,
    'audit alert carries audit tag')
    if $event_audit;

done_testing();
