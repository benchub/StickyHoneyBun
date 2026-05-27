#!/usr/bin/env ruby
#
# ORM tester: ActiveRecord (Rails' default ORM).
#
# Mirrors the Python testers' idiomatic "fetch all rows" call. The
# `.all.to_a` materializes every row via the standard `SELECT` path;
# typeoutput fires for the honey column and the trap logs an alert.
#
# Connects via libpq env vars. ActiveRecord's PG adapter doesn't
# fall back to libpq env automatically (unlike psql / psycopg2), so
# we pass each piece explicitly.

require 'active_record'

ActiveRecord::Base.establish_connection(
  adapter:  'postgresql',
  host:     ENV['PGHOST'],
  port:     ENV['PGPORT'].to_i,
  username: ENV['PGUSER'],
  database: ENV['PGDATABASE'],
)

class HoneyTable < ActiveRecord::Base
  self.table_name = 'honey_table'
end

rows = HoneyTable.all.order(:id).to_a
first_honey = rows.first ? rows.first.honey.inspect : 'none'
STDERR.puts "activerecord: fetched #{rows.size} row(s); first honey value = #{first_honey}"
