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
--
-- Installation:
--   psql ... -f sticky_honey_bun_rds.sql
--   CREATE EXTENSION sticky_honey_bun_rds;
--   -- Then populate the locked-down config table (PUBLIC has no access;
--   -- run as the extension owner):
--   INSERT INTO sticky_honey_bun_rds_config(key, value) VALUES
--     ('lambda_arn', 'arn:aws:lambda:REGION:ACCOUNT:function:NAME'),
--     ('cluster_id', 'my-cluster')   -- optional
--   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
--
-- Configuration storage rationale: RDS rejects custom-namespace GUCs in
-- parameter groups, and `ALTER DATABASE/ROLE SET sticky_honey_bun_rds.foo`
-- errors with "permission denied to set parameter". Even if those routes
-- worked, custom-namespace GUCs are user-settable per session, so an
-- attacker could SET sticky_honey_bun_rds.lambda_arn = '' to silence
-- their own queries. A locked-down config table read via SECURITY DEFINER
-- is the tamper-resistant alternative.

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
    -- Defer the type lookup to call time. With `'honey_bun'::regtype`
    -- (or even bare `'honey_bun'` if PG picks the oid overload of
    -- has_type_privilege), the type name is resolved at function-parse
    -- time — too early during CREATE EXTENSION because honey_bun isn't
    -- created until pgtle.create_base_type runs further down in this
    -- install body. Force the text-name overload with explicit ::text
    -- on the literal so PG doesn't try the oid path.
    IF NOT has_type_privilege(current_user, 'honey_bun'::text, 'USAGE') THEN
        RAISE EXCEPTION 'permission denied for type honey_bun'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN convert_to(input, 'UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;

-- Locked-down config table. Holds lambda_arn and cluster_id (and any
-- future config) per-database. PUBLIC has NO access; an attacker
-- session cannot read these values to discover the Lambda ARN, and
-- cannot UPDATE them to silence the trap. The trap function below
-- reads this table via SECURITY DEFINER, running as the extension's
-- owner (which has SELECT by default), so legitimate trap fires still
-- work.
--
-- This replaces the GUC-based config the earlier RDS variant used.
-- On RDS, custom-namespace GUCs are settable per-session by any role
-- (`SET sticky_honey_bun_rds.lambda_arn = ''` would silence the trap
-- for an attacker's own queries), and rds_superuser cannot set them
-- at the database/role level either ("permission denied to set
-- parameter"). A locked-down table is the tamper-resistant alternative.
CREATE TABLE sticky_honey_bun_rds_config (
    key   text PRIMARY KEY,
    value text
);
REVOKE ALL ON sticky_honey_bun_rds_config FROM PUBLIC;
COMMENT ON TABLE sticky_honey_bun_rds_config IS
    'Locked-down config for sticky_honey_bun_rds. PUBLIC has no access. '
    'Modify as the extension owner: INSERT INTO sticky_honey_bun_rds_config '
    'VALUES (''lambda_arn'', ''arn:aws:lambda:...''), '
    '(''cluster_id'', ''my-cluster'') '
    'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;';

-- IMMUTABLE is technically a lie (we read a table and invoke a Lambda),
-- but PG enforces that typeoutput functions be IMMUTABLE. Same trade-off
-- the C variant makes — see README's "I/O functions are declared
-- IMMUTABLE" note. Constant-folding doesn't apply to the executor's
-- typoutput dispatch path (SELECT/COPY/pg_dump), so the side effect
-- still fires per row.
CREATE FUNCTION honey_bun_out_rds(stored bytea)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE STRICT
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    tag        text := convert_from(stored, 'UTF8');
    arn        text;
    cluster_id text;
    payload    jsonb;
BEGIN
    -- Read locked-down config. PUBLIC cannot reach this table directly,
    -- but SECURITY DEFINER means we run as the extension owner, which has
    -- SELECT by default. An attacker session cannot silence the trap by
    -- modifying these values — they have no GRANTs.
    SELECT value INTO arn
      FROM sticky_honey_bun_rds_config
     WHERE key = 'lambda_arn';
    IF arn IS NULL OR arn = '' THEN
        -- No Lambda configured — return the tag without firing. Lets the
        -- extension be installed before the Lambda exists.
        RETURN tag;
    END IF;
    SELECT value INTO cluster_id
      FROM sticky_honey_bun_rds_config
     WHERE key = 'cluster_id';

    payload := jsonb_build_object(
        'ts',               to_char(clock_timestamp() AT TIME ZONE 'UTC',
                                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'event',            'read_text',
        'tag',              tag,
        'session_user',     session_user::text,
        -- SECURITY DEFINER changes `current_user` to the function
        -- owner — so a naive `current_user::text` would report the
        -- extension owner even when the caller has done SET ROLE.
        -- Reconstruct the caller's real current_user from the `role`
        -- GUC: it persists across the SECURITY DEFINER boundary and
        -- holds the SET ROLE target ('none' when no role pivot is in
        -- effect, in which case current_user == session_user for the
        -- caller).
        'current_user',     CASE WHEN current_setting('role') = 'none'
                                 THEN session_user::text
                                 ELSE current_setting('role')
                            END,
        'application_name', current_setting('application_name', true),
        'database',         current_database()::text,
        'pid',              pg_backend_pid(),
        'client_addr',      coalesce(inet_client_addr()::text, 'local'),
        'query',            current_query(),
        'cluster_id',       coalesce(cluster_id,
                                    inet_server_addr()::text,
                                    'unknown'),
        -- Always-populated per-node identifier. cluster_id is meant
        -- for cross-cluster fan-in routing, and on an RDS read replica
        -- it inherits the primary's value (the config table is WAL-
        -- replicated). server_addr is the address of the actual
        -- PostgreSQL backend that handled the read — different per
        -- node within a cluster, so alerts from a primary vs a
        -- replica are always distinguishable. Falls back to 'local'
        -- for unix-socket connections (typical of self-hosted, never
        -- happens on RDS).
        'server_addr',      coalesce(inet_server_addr()::text, 'local')
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
$$;

-- Mirror of the self-hosted variant's I/O-function lockdown. PG's typinput
-- and typoutput dispatch paths bypass function ACLs, so the REVOKE alone
-- can't block 'forged'::honey_bun — but the has_type_privilege guard inside
-- honey_bun_in_rds covers the cast path, and the REVOKE closes the direct
-- SELECT honey_bun_in_rds(...) call path.
REVOKE EXECUTE ON FUNCTION honey_bun_in_rds(text)   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION honey_bun_out_rds(bytea) FROM PUBLIC;

-- pg_tle requires a shell type to exist before create_base_type can
-- promote it to a full base type. The shell type lets the I/O functions'
-- has_type_privilege check resolve the name when they're called later.
SELECT pgtle.create_shell_type('public', 'honey_bun');

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
    in_fn_name  name := 'shb_' || type_name || '_in';
    out_fn_name name := 'shb_' || type_name || '_out';
BEGIN
    -- Per-alias I/O function wrappers. Two pg_tle constraints force
    -- this indirection:
    --   1. "type input functions must exist in the same namespace as
    --      the type" — pg_tle.create_base_type rejects an alias in
    --      schema X whose input function lives in schema Y. So the
    --      wrappers go in the alias's own schema.
    --   2. pg_tle's internal wrapper construction reuses the user-
    --      supplied function name, so passing the canonical
    --      `honey_bun_in_rds` for every alias produces "function
    --      already exists" on the second alias. Per-alias names sidestep
    --      that collision.
    -- The wrappers are thin SQL delegates back to the canonical
    -- honey_bun_in_rds / honey_bun_out_rds in public — the heavy
    -- logic (has_type_privilege guard, Lambda invoke) stays in one
    -- place rather than being duplicated per alias.
    EXECUTE format(
        'CREATE FUNCTION %I.%I(input text) RETURNS bytea '
     || 'LANGUAGE sql IMMUTABLE STRICT '
     || 'AS ''SELECT public.honey_bun_in_rds(input)''',
        type_schema, in_fn_name);
    EXECUTE format(
        'CREATE FUNCTION %I.%I(stored bytea) RETURNS text '
     || 'LANGUAGE sql IMMUTABLE STRICT '
     || 'AS ''SELECT public.honey_bun_out_rds(stored)''',
        type_schema, out_fn_name);

    -- pg_tle's create_shell_type / create_base_type declare their first
    -- arg as `regnamespace`. PG resolves a bare string literal to either
    -- `name` OR `regnamespace` at parse time, but a PL/pgSQL variable of
    -- type `name` does NOT implicitly cast to regnamespace at
    -- function-call resolution time — `function pgtle.create_shell_type
    -- (name, name) does not exist`. Explicit cast makes the dispatch
    -- unambiguous.
    PERFORM pgtle.create_shell_type(type_schema::regnamespace, type_name);
    PERFORM pgtle.create_base_type(
        type_schema::regnamespace, type_name,
        format('%I.%I(text)',  type_schema, in_fn_name)::regprocedure,
        format('%I.%I(bytea)', type_schema, out_fn_name)::regprocedure,
        -1);

    new_type := format('%I.%I', type_schema, type_name)::regtype;
    INSERT INTO honey_bun_registry VALUES (new_type);
    -- Mirror the canonical type's USAGE lockdown so an alias doesn't
    -- reopen the indirect-forge path, and REVOKE EXECUTE on the
    -- per-alias delegates so they're not a back door around the I/O
    -- function ACL.
    EXECUTE format('REVOKE USAGE ON TYPE %s FROM PUBLIC', new_type);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %I.%I(text) FROM PUBLIC',
        type_schema, in_fn_name);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %I.%I(bytea) FROM PUBLIC',
        type_schema, out_fn_name);
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
