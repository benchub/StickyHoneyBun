-- Sticky Honey Bun (RDS / Aurora variant)
--
-- Packages honey_bun as a Trusted Language Extension via pg_tle. The output
-- function is PL/pgSQL and invokes aws_lambda.invoke() fire-and-forget to ship
-- the alert event off-cluster.
--
-- Prerequisites on the target cluster:
--   - pg_tle extension installed (rds.allowed_extensions / aurora.allowed_extensions
--     parameter must list 'pg_tle', and CREATE EXTENSION pg_tle has run).
--   - aws_lambda extension installed (CREATE EXTENSION aws_lambda).
--   - IAM role attached to the RDS instance with lambda:InvokeFunction on the
--     target Lambda.
--   - Custom GUC sticky_honey_bun_rds.lambda_arn set in the parameter group.
--
-- Installation:
--   psql ... -f sticky_honey_bun_rds.sql
--   CREATE EXTENSION sticky_honey_bun_rds;

SELECT pgtle.install_extension(
    'sticky_honey_bun_rds',
    '1.0',
    'Sticky Honey Bun honeytoken type (RDS / Aurora variant via pg_tle)',
$_pgtle_$

CREATE FUNCTION honey_bun_in_rds(input text)
RETURNS bytea
AS $$
BEGIN
    -- Defense in depth: PG's typinput dispatch (and pg_tle's wrapper around
    -- it) bypasses function ACLs, so REVOKE EXECUTE on this function alone
    -- is insufficient to block 'forged'::honey_bun. Require USAGE on the
    -- canonical honey_bun type; admins who grant USAGE on an alias only
    -- should also grant on canonical (the simpler model).
    IF NOT has_type_privilege(current_user, 'honey_bun'::regtype, 'USAGE') THEN
        RAISE EXCEPTION 'permission denied for type honey_bun'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN convert_to(input, 'UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

CREATE FUNCTION honey_bun_out_rds(stored bytea)
RETURNS text
AS $$
DECLARE
    tag     text := convert_from(stored, 'UTF8');
    arn     text := current_setting('sticky_honey_bun_rds.lambda_arn', true);
    payload jsonb;
BEGIN
    -- No kill-switch GUC: pg_tle base extensions cannot register GUCs with
    -- PGC_POSTMASTER context, so any "enabled" flag would be settable per
    -- session via SET and trivially bypassable. Disabling on RDS is a
    -- DROP EXTENSION (or unsetting lambda_arn) operation.
    IF arn IS NULL OR arn = '' THEN
        RETURN tag;
    END IF;

    payload := jsonb_build_object(
        'ts',               to_char(clock_timestamp() AT TIME ZONE 'UTC',
                                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'event',            'read_text',
        'tag',              tag,
        'session_user',     session_user::text,
        'current_user',     current_user::text,
        'application_name', current_setting('application_name', true),
        'database',         current_database()::text,
        'pid',              pg_backend_pid(),
        'client_addr',      coalesce(inet_client_addr()::text, 'local'),
        'query',            current_query(),
        'cluster_id',       coalesce(
                                current_setting('sticky_honey_bun_rds.cluster_id', true),
                                inet_server_addr()::text,
                                'unknown'
                            )
    );

    BEGIN
        PERFORM aws_lambda.invoke(
            function_name   := arn,
            payload         := payload,
            invocation_type := 'Event'
        );
    EXCEPTION WHEN OTHERS THEN
        -- Swallow all errors so a broken Lambda or revoked IAM permission
        -- never surfaces as a query error and unmasks the trap.
        NULL;
    END;

    RETURN tag;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- Mirror of the self-hosted variant's I/O-function lockdown. PG's typinput
-- and typoutput dispatch paths bypass function ACLs, so the REVOKE alone
-- can't block 'forged'::honey_bun — but the has_type_privilege guard inside
-- honey_bun_in_rds covers the cast path, and the REVOKE closes the direct
-- SELECT honey_bun_in_rds(...) call path.
REVOKE EXECUTE ON FUNCTION honey_bun_in_rds(text)   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION honey_bun_out_rds(bytea) FROM PUBLIC;

SELECT pgtle.create_base_type(
    'public',
    'honey_bun',
    'honey_bun_in_rds(text)'::regprocedure,
    'honey_bun_out_rds(bytea)'::regprocedure,
    -1
);

-- USAGE on the type is checked when a column of this type is created or
-- when a function references it. Closes the indirect-forge path where an
-- attacker would otherwise CREATE TABLE forge (h honey_bun); INSERT …;
-- SELECT … to fire alerts. Operators who want a specific planter role
-- should GRANT USAGE ON TYPE honey_bun TO that_role on this cluster.
REVOKE USAGE ON TYPE honey_bun FROM PUBLIC;

-- Registry of honey-shaped types created by this extension. pg_tle wraps
-- typinput/typoutput internally, so we cannot reliably identify aliases by
-- inspecting pg_proc.prosrc the way the self-hosted C variant does.
CREATE TABLE honey_bun_registry (type_oid oid PRIMARY KEY);
INSERT INTO honey_bun_registry VALUES ('honey_bun'::regtype);

CREATE VIEW honey_bun_columns AS
    SELECT n.nspname  AS schema_name,
           c.relname  AS table_name,
           a.attname  AS column_name,
           tn.nspname || '.' || t.typname AS type_name
      FROM honey_bun_registry r
      JOIN pg_type      t  ON t.oid = r.type_oid
      JOIN pg_attribute a  ON a.atttypid = t.oid
      JOIN pg_class     c  ON a.attrelid = c.oid
      JOIN pg_namespace n  ON c.relnamespace = n.oid
      JOIN pg_namespace tn ON t.typnamespace = tn.oid
     WHERE NOT a.attisdropped
       AND a.attnum > 0
       AND c.relkind IN ('r', 'p')
     ORDER BY 1, 2, 3;

COMMENT ON VIEW honey_bun_columns IS
    'Inventory of every column declared with a honey_bun-shaped type, '
    'including any aliases created via create_honey_bun_alias.';

-- Locked down by default: the view is a one-stop enumeration of every
-- planted trap (including aliases). GRANT SELECT to a narrow audit role
-- when needed. Public has no business reading this.
REVOKE ALL ON honey_bun_columns FROM PUBLIC;
REVOKE ALL ON honey_bun_registry FROM PUBLIC;

-- Site-specific aliases. Unlike the C variant, pg_tle base types can share
-- I/O function signatures, so each alias just registers a new type pointing
-- at the same PL/pgSQL implementations.
CREATE FUNCTION create_honey_bun_alias(type_name name,
                                       type_schema name DEFAULT current_schema())
RETURNS regtype
LANGUAGE plpgsql
AS $$
DECLARE
    new_type regtype;
BEGIN
    PERFORM pgtle.create_base_type(
        type_schema,
        type_name,
        'honey_bun_in_rds(text)'::regprocedure,
        'honey_bun_out_rds(bytea)'::regprocedure,
        -1
    );
    new_type := format('%I.%I', type_schema, type_name)::regtype;
    INSERT INTO honey_bun_registry VALUES (new_type);
    -- Mirror the canonical type's USAGE lockdown so an alias doesn't
    -- reopen the indirect-forge path.
    EXECUTE format('REVOKE USAGE ON TYPE %s FROM PUBLIC', new_type);
    RETURN new_type;
END;
$$;

REVOKE EXECUTE ON FUNCTION create_honey_bun_alias(name, name) FROM PUBLIC;

COMMENT ON FUNCTION create_honey_bun_alias(name, name) IS
    'Register a new honey-shaped type under a site-specific name. Reads of '
    'columns of this type fire the same Lambda invocation as honey_bun.';

$_pgtle_$,
    ARRAY['pg_tle', 'aws_lambda']
);
