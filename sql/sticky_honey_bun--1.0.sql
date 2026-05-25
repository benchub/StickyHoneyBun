\echo Use "CREATE EXTENSION sticky_honey_bun" to load this file. \quit

CREATE TYPE honey_bun;

CREATE FUNCTION honey_bun_in(cstring)
    RETURNS honey_bun
    AS 'MODULE_PATHNAME', 'honey_bun_in'
    LANGUAGE C IMMUTABLE STRICT;

-- The out/send functions have a filesystem side effect but do not modify
-- database state and always return the same cstring/bytea for a given
-- input. Marking them IMMUTABLE (a) silences PG's "should not be volatile"
-- CREATE TYPE warning and (b) leaves the typeoutput dispatch path
-- unaffected (the executor doesn't fold typeio invocations). The one edge
-- case is constant-folding of SQL-level direct calls, which we don't use.

CREATE FUNCTION honey_bun_out(honey_bun)
    RETURNS cstring
    AS 'MODULE_PATHNAME', 'honey_bun_out'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION honey_bun_recv(internal)
    RETURNS honey_bun
    AS 'MODULE_PATHNAME', 'honey_bun_recv'
    LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION honey_bun_send(honey_bun)
    RETURNS bytea
    AS 'MODULE_PATHNAME', 'honey_bun_send'
    LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE honey_bun (
    INPUT          = honey_bun_in,
    OUTPUT         = honey_bun_out,
    RECEIVE        = honey_bun_recv,
    SEND           = honey_bun_send,
    INTERNALLENGTH = VARIABLE,
    STORAGE        = extended,
    CATEGORY       = 'S'
);

COMMENT ON TYPE honey_bun IS
    'Sticky Honey Bun honeytoken type. The stored value is a tag identifying '
    'the trap location (e.g., schema.table.column). Reading the value fires '
    'a side effect that logs the access to the alert file.';

-- Comparison and hash support so DISTINCT/ORDER BY/MIN/MAX/GROUP BY work.
-- honey_bun's internal layout matches varlena, so we bind to PG's bytea
-- internal symbols. bytea comparison is collation-independent, which avoids
-- the "could not determine which collation to use" trap that text-based
-- hashing would hit.

CREATE FUNCTION honey_bun_eq(honey_bun, honey_bun)  RETURNS bool
    AS 'byteaeq'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_ne(honey_bun, honey_bun)  RETURNS bool
    AS 'byteane'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_lt(honey_bun, honey_bun)  RETURNS bool
    AS 'bytealt'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_le(honey_bun, honey_bun)  RETURNS bool
    AS 'byteale'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_gt(honey_bun, honey_bun)  RETURNS bool
    AS 'byteagt'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_ge(honey_bun, honey_bun)  RETURNS bool
    AS 'byteage'   LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_cmp(honey_bun, honey_bun) RETURNS int
    AS 'byteacmp'  LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;
CREATE FUNCTION honey_bun_hash(honey_bun)           RETURNS int
    AS 'hashvarlena' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;

CREATE OPERATOR = (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_eq,
    COMMUTATOR = =, NEGATOR = <>,
    HASHES, MERGES);
CREATE OPERATOR <> (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_ne,
    COMMUTATOR = <>, NEGATOR = =);
CREATE OPERATOR < (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_lt,
    COMMUTATOR = >, NEGATOR = >=);
CREATE OPERATOR <= (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_le,
    COMMUTATOR = >=, NEGATOR = >);
CREATE OPERATOR > (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_gt,
    COMMUTATOR = <, NEGATOR = <=);
CREATE OPERATOR >= (
    LEFTARG = honey_bun, RIGHTARG = honey_bun,
    PROCEDURE = honey_bun_ge,
    COMMUTATOR = <=, NEGATOR = <);

CREATE OPERATOR CLASS honey_bun_ops
    DEFAULT FOR TYPE honey_bun USING btree AS
    OPERATOR 1 <,
    OPERATOR 2 <=,
    OPERATOR 3 =,
    OPERATOR 4 >=,
    OPERATOR 5 >,
    FUNCTION 1 honey_bun_cmp(honey_bun, honey_bun);

CREATE OPERATOR CLASS honey_bun_hash_ops
    DEFAULT FOR TYPE honey_bun USING hash AS
    OPERATOR 1 =,
    FUNCTION 1 honey_bun_hash(honey_bun);

-- MIN / MAX aggregates. PG defines these per built-in type; user-defined
-- types need their own. The state transition functions use our < / >
-- operators above (so still byte-level, no collation needed).
CREATE FUNCTION honey_bun_smaller(honey_bun, honey_bun) RETURNS honey_bun
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
    'SELECT CASE WHEN $1 < $2 THEN $1 ELSE $2 END';
CREATE FUNCTION honey_bun_larger(honey_bun, honey_bun)  RETURNS honey_bun
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS
    'SELECT CASE WHEN $1 > $2 THEN $1 ELSE $2 END';

CREATE AGGREGATE min(honey_bun) (
    SFUNC       = honey_bun_smaller,
    STYPE       = honey_bun,
    SORTOP      = <,
    PARALLEL    = SAFE,
    COMBINEFUNC = honey_bun_smaller);

CREATE AGGREGATE max(honey_bun) (
    SFUNC       = honey_bun_larger,
    STYPE       = honey_bun,
    SORTOP      = >,
    PARALLEL    = SAFE,
    COMBINEFUNC = honey_bun_larger);

CREATE VIEW honey_bun_columns AS
    SELECT n.nspname  AS schema_name,
           c.relname  AS table_name,
           a.attname  AS column_name,
           tn.nspname || '.' || t.typname AS type_name
      FROM pg_attribute  a
      JOIN pg_class      c   ON a.attrelid = c.oid
      JOIN pg_namespace  n   ON c.relnamespace = n.oid
      JOIN pg_type       t   ON a.atttypid = t.oid
      JOIN pg_namespace  tn  ON t.typnamespace = tn.oid
      JOIN pg_proc       fn  ON t.typoutput = fn.oid
      JOIN pg_language   lng ON fn.prolang = lng.oid
     WHERE fn.prosrc  = 'honey_bun_out'
       AND lng.lanname = 'c'
       AND NOT a.attisdropped
       AND a.attnum > 0
       AND c.relkind IN ('r', 'p')
     ORDER BY 1, 2, 3;

COMMENT ON VIEW honey_bun_columns IS
    'Inventory of every column whose type shares honey_bun''s C output '
    'function (including aliases created via create_honey_bun_alias).';

-- The inventory view enumerates every planted honey column under every
-- aliased type name. That is exactly the catalog an attacker with database
-- access wants, so deny everyone by default. Operators GRANT SELECT to a
-- narrowly-scoped audit role when needed.
REVOKE ALL ON honey_bun_columns FROM PUBLIC;

CREATE FUNCTION create_honey_bun_alias(type_name name,
                                         type_schema name DEFAULT current_schema())
RETURNS regtype
LANGUAGE plpgsql
AS $$
DECLARE
    qualified text := format('%I.%I', type_schema, type_name);
    in_fn   text := format('%I.%I_in',   type_schema, type_name);
    out_fn  text := format('%I.%I_out',  type_schema, type_name);
    recv_fn text := format('%I.%I_recv', type_schema, type_name);
    send_fn text := format('%I.%I_send', type_schema, type_name);
    eq_fn   text := format('%I.%I_eq',   type_schema, type_name);
    ne_fn   text := format('%I.%I_ne',   type_schema, type_name);
    lt_fn   text := format('%I.%I_lt',   type_schema, type_name);
    le_fn   text := format('%I.%I_le',   type_schema, type_name);
    gt_fn   text := format('%I.%I_gt',   type_schema, type_name);
    ge_fn   text := format('%I.%I_ge',   type_schema, type_name);
    cmp_fn  text := format('%I.%I_cmp',  type_schema, type_name);
    hash_fn text := format('%I.%I_hash', type_schema, type_name);
BEGIN
    -- Shell type so we can reference it in the I/O functions' signatures.
    EXECUTE format('CREATE TYPE %s', qualified);

    -- Per-alias SQL bindings that point at the same C implementations
    -- as honey_bun. PG enforces that each type's I/O functions return
    -- that type, so we can't share the SQL-level functions.
    EXECUTE format(
        'CREATE FUNCTION %s(cstring) RETURNS %s
            AS ''$libdir/sticky_honey_bun'', ''honey_bun_in''
            LANGUAGE C IMMUTABLE STRICT',
        in_fn, qualified);

    EXECUTE format(
        'CREATE FUNCTION %s(%s) RETURNS cstring
            AS ''$libdir/sticky_honey_bun'', ''honey_bun_out''
            LANGUAGE C IMMUTABLE STRICT',
        out_fn, qualified);

    EXECUTE format(
        'CREATE FUNCTION %s(internal) RETURNS %s
            AS ''$libdir/sticky_honey_bun'', ''honey_bun_recv''
            LANGUAGE C IMMUTABLE STRICT',
        recv_fn, qualified);

    EXECUTE format(
        'CREATE FUNCTION %s(%s) RETURNS bytea
            AS ''$libdir/sticky_honey_bun'', ''honey_bun_send''
            LANGUAGE C IMMUTABLE STRICT',
        send_fn, qualified);

    EXECUTE format(
        'CREATE TYPE %s ('
        '  INPUT          = %s,'
        '  OUTPUT         = %s,'
        '  RECEIVE        = %s,'
        '  SEND           = %s,'
        '  INTERNALLENGTH = VARIABLE,'
        '  STORAGE        = extended,'
        '  CATEGORY       = ''S'')',
        qualified, in_fn, out_fn, recv_fn, send_fn);

    -- Comparison/hash functions bound to PG's bytea internal symbols
    -- (collation-independent, same as the canonical honey_bun setup).
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''byteaeq'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        eq_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''byteane'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        ne_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''bytealt'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        lt_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''byteale'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        le_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''byteagt'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        gt_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS bool
        AS ''byteage'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        ge_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s, %s) RETURNS int
        AS ''byteacmp'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        cmp_fn, qualified, qualified);
    EXECUTE format('CREATE FUNCTION %s(%s) RETURNS int
        AS ''hashvarlena'' LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE',
        hash_fn, qualified);

    EXECUTE format(
        'CREATE OPERATOR = (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = =, NEGATOR = <>, HASHES, MERGES)',
        qualified, qualified, eq_fn);
    EXECUTE format(
        'CREATE OPERATOR <> (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = <>, NEGATOR = =)',
        qualified, qualified, ne_fn);
    EXECUTE format(
        'CREATE OPERATOR < (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = >, NEGATOR = >=)',
        qualified, qualified, lt_fn);
    EXECUTE format(
        'CREATE OPERATOR <= (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = >=, NEGATOR = >)',
        qualified, qualified, le_fn);
    EXECUTE format(
        'CREATE OPERATOR > (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = <, NEGATOR = <=)',
        qualified, qualified, gt_fn);
    EXECUTE format(
        'CREATE OPERATOR >= (LEFTARG = %s, RIGHTARG = %s, PROCEDURE = %s,
            COMMUTATOR = <=, NEGATOR = <)',
        qualified, qualified, ge_fn);

    EXECUTE format(
        'CREATE OPERATOR CLASS %I.%I_ops DEFAULT FOR TYPE %s USING btree AS
            OPERATOR 1 <, OPERATOR 2 <=, OPERATOR 3 =,
            OPERATOR 4 >=, OPERATOR 5 >,
            FUNCTION 1 %s(%s, %s)',
        type_schema, type_name, qualified, cmp_fn, qualified, qualified);

    EXECUTE format(
        'CREATE OPERATOR CLASS %I.%I_hash_ops DEFAULT FOR TYPE %s USING hash AS
            OPERATOR 1 =,
            FUNCTION 1 %s(%s)',
        type_schema, type_name, qualified, hash_fn, qualified);

    -- min/max aggregates and their state functions.
    EXECUTE format(
        'CREATE FUNCTION %I.%I_smaller(%s, %s) RETURNS %s
            LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
            AS ''SELECT CASE WHEN $1 < $2 THEN $1 ELSE $2 END''',
        type_schema, type_name, qualified, qualified, qualified);
    EXECUTE format(
        'CREATE FUNCTION %I.%I_larger(%s, %s) RETURNS %s
            LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
            AS ''SELECT CASE WHEN $1 > $2 THEN $1 ELSE $2 END''',
        type_schema, type_name, qualified, qualified, qualified);

    EXECUTE format(
        'CREATE AGGREGATE min(%s) (
            SFUNC       = %I.%I_smaller,
            STYPE       = %s,
            SORTOP      = <,
            PARALLEL    = SAFE,
            COMBINEFUNC = %I.%I_smaller)',
        qualified, type_schema, type_name, qualified, type_schema, type_name);

    EXECUTE format(
        'CREATE AGGREGATE max(%s) (
            SFUNC       = %I.%I_larger,
            STYPE       = %s,
            SORTOP      = >,
            PARALLEL    = SAFE,
            COMBINEFUNC = %I.%I_larger)',
        qualified, type_schema, type_name, qualified, type_schema, type_name);

    RETURN qualified::regtype;
END;
$$;

COMMENT ON FUNCTION create_honey_bun_alias(name, name) IS
    'Create a new honeytoken type sharing honey_bun''s C-level I/O '
    'implementations under a site-specific name. Lets you plant traps '
    'without "honey_bun" appearing in the catalog.';
