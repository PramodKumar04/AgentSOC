-- SYNTHETIC test fixture for tests/integration/test_postgres_real.py.
-- Run as a database owner on a TEST server only, never on an organisation's database:
--   psql -h localhost -U postgres -d agentsoc_test -f scripts/postgres_test_fixture.sql
-- Then set the reader password (not stored in this file):
--   ALTER ROLE agentsoc_reader PASSWORD '...';
-- Creates a table of 1,000 generated authentication rows and a role granted SELECT only.

DROP SCHEMA IF EXISTS agentsoc_fixture CASCADE;
CREATE SCHEMA agentsoc_fixture;

CREATE TABLE agentsoc_fixture.auth_events (
    id            bigint PRIMARY KEY,
    ingested_at   timestamptz NOT NULL,
    event_time    timestamptz NOT NULL,
    account       text NOT NULL,
    client        text NOT NULL,
    server        text NOT NULL,
    action        text NOT NULL,
    result        boolean NOT NULL,
    note          text            -- not mapped: must never be read
);

INSERT INTO agentsoc_fixture.auth_events
SELECT g,
       timestamptz '2026-11-01 00:00:00+00' + g * interval '7 seconds' + interval '1 second',
       timestamptz '2026-11-01 00:00:00+00' + g * interval '7 seconds',
       'user' || (g % 25) || '@CORP',
       'WS-' || (g % 40),
       'SRV-' || (g % 6),
       CASE WHEN g % 50 = 0 THEN 'Unlock' ELSE 'LogOn' END,  -- 20 rows must be rejected
       g % 9 <> 0,
       'SYNTHETIC fixture row'
FROM generate_series(1, 1000) AS g;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agentsoc_reader') THEN
        CREATE ROLE agentsoc_reader LOGIN;
    END IF;
END $$;
REVOKE ALL ON SCHEMA agentsoc_fixture FROM agentsoc_reader;
GRANT USAGE ON SCHEMA agentsoc_fixture TO agentsoc_reader;
GRANT SELECT ON agentsoc_fixture.auth_events TO agentsoc_reader;
