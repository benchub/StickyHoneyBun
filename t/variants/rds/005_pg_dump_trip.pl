#!/usr/bin/perl
# Variants: self-hosted, rds
# Asserts: pg_dump's COPY-based data extraction fires the trap. The
#          dump output leaks the planted tag (data exfiltrated through
#          the dump, as designed for legitimate backups) AND Lambda
#          receives an alert whose query field contains "COPY".

use strict;
use warnings;
use lib 't/lib';
use Test::More;
use SHB_RDS;
use SHB_Assertions;

# pg_dump must be available locally AND its major version must match
# the RDS server, or pg_dump refuses ("aborting because of server
# version mismatch"). Skip cleanly when prerequisites aren't met —
# operators who want to exercise this path should install a pg_dump
# matching their RDS engine version.
my $pg_dump = `which pg_dump`;
chomp $pg_dump;
plan skip_all => 'pg_dump not on PATH' unless $pg_dump;

my $dump_version_line = `pg_dump --version 2>&1`;
my ($dump_major) = $dump_version_line =~ /pg_dump \(PostgreSQL\)\s+(\d+)/;
plan skip_all => "could not parse pg_dump version from: $dump_version_line"
    unless defined $dump_major;

my $st  = SHB_RDS::load_state();

# Probe the RDS server's major version. pg_dump abort happens before
# any output, so we have to detect mismatch ourselves; SELECT
# current_setting('server_version_num') gives us the canonical number.
{
    my $probe_cs = SHB_RDS::connstr($st);
    my (undef, $sv) = SHB_RDS::psql_run($probe_cs,
        "SELECT current_setting('server_version_num')::int / 10000");
    chomp $sv;
    plan skip_all =>
        "pg_dump major ($dump_major) < RDS server major ($sv); "
      . 'install a matching client (brew install postgresql@' . $sv . ')'
        if $dump_major < $sv;
}


my $cs  = SHB_RDS::schema_setup($st, 'shb_t005');
my $get_event = SHB_RDS::get_event_fn($st);
my $run = sub { SHB_RDS::psql_run($cs, $_[0]) };

$run->('CREATE TABLE t (id int, honey honey_bun)');
my $tag = SHB_RDS::unique_tag($st, 'pg_dump');
$run->("INSERT INTO t VALUES (1, '$tag')");

# Run pg_dump against just our test schema's table. Use libpq env vars
# so we don't have to embed the password in argv (psql logs argv).
my $host = $st->{endpoint}{host};
my $port = $st->{endpoint}{port};
my $user = $st->{master_user};
my $pw   = $st->{master_password};

local $ENV{PGPASSWORD} = $pw;
my ($rc, $dump_out, $dump_err) = SHB_RDS::run_cmd([
    'pg_dump',
    '-h', $host, '-p', $port, '-U', $user, '-d', 'postgres',
    '--no-owner', '--no-acl',
    '-t', 'shb_t005.t',
    '--data-only',
]);

is($rc, 0, 'pg_dump succeeds against RDS instance')
    or diag("pg_dump stderr: $dump_err");

# Data was leaked through the dump — pg_dump's COPY transport read the
# honey row via typeoutput dispatch. This is BY DESIGN; the alert is
# how the trap fires to notify the operator.
like($dump_out, qr/\Q$tag\E/,
    'pg_dump output contains the planted honey tag (data exfiltrated)');

# Lambda received the alert with COPY in the query field.
my $event = $get_event->($tag);
ok($event, 'pg_dump fired the trap');
is($event->{tag},   $tag,        'alert tag matches planted value') if $event;
is($event->{event}, 'read_text', 'alert event=read_text')           if $event;
like($event->{query}, qr/COPY/i,
    'alert query field carries the COPY statement')
    if $event;

done_testing();
