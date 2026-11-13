# Connecting an organisation's database (PostgreSQL)

**Status: built and tested against a simulated database only. Not yet verified against a
real PostgreSQL server** (`tests/integration/test_postgres_real.py` is skipped until one is
configured).

## Before you start

1. Set a credential key, otherwise no database password can be stored:
   `python scripts/manage_credentials.py generate-key`, put the key in
   `AGENTSOC_CREDENTIAL_KEY` (in `.env`) and restart. See
   [security_foundations.md](security_foundations.md) for backup and rotation.
2. On the database, create an account that can **only SELECT** the one table or view:
   ```sql
   CREATE ROLE agentsoc_reader LOGIN PASSWORD '...';
   GRANT USAGE ON SCHEMA security TO agentsoc_reader;
   GRANT SELECT ON security.auth_events TO agentsoc_reader;
   ```
   AgentSOC also makes every session read-only, with a 30 s statement timeout, and warns
   if the account is a superuser or can create objects.
3. Use TLS `verify-full` outside a test network.

## Setting it up (administrator)

**Database Connections** in the menu: connect → choose the table → map columns → preview the
first 50 rows (nothing is stored) → save. Then *Sync now*, *Update dashboard snapshot*, and
*Start scheduled sync*.

- **Record identifier**: a unique column (the primary key). It becomes the event ID
  (`<source key>.<id>`), so every event leads back to its row.
- **Read new rows in order of**: a column that only grows for new rows (an ID sequence or an
  "inserted at" time), not the event time.
- **Look-back**: re-reads that far behind the checkpoint on each sync to catch rows committed
  late. Rows already stored are skipped.
- **Required fields**: user, source host, destination host, event kind (orientation) and
  outcome. A field the table does not have can be set to one fixed value only if you tick the
  confirmation. That choice is shown on the source and in its dataset's `mapping.json`.
- Values are never guessed. A row with an unmapped event kind or outcome, a time without a time
  zone (unless you name one), or characters AgentSOC does not accept is **rejected with the
  reason** and counted per source.

## How "live" it is

AgentSOC **polls**. It is not real-time and not streaming. Each enabled source is checked every
N seconds (at least 30), and new rows are stored. At most every 5 minutes, the newest rows (up
to 7 days and 200,000 events) are frozen into a **snapshot** and analysed by the unchanged
detection, attack-path (SSE) and risk (RSEM) engines. The dashboard shows the latest snapshot as
the data source *"<name> (organisation database, snapshot …)"* with real times in UTC.

Expect a delay of one sync interval, plus up to the snapshot interval, plus the analysis time.

## AI investigation

Off for every organisational source. An administrator can allow it per source after reading
and accepting the warning that the incident's evidence (user names, host names, times,
outcomes) is sent to the external language-model provider. Who changed it, and when, is shown
and audited. While it is off, investigations use the local deterministic analysis only, and
the provider is never called.

## Guarantees and limits

- Each row is stored once, keyed by its record ID, so re-reading after a failure or a reset
  adds nothing twice. A row that changes at the source under the same ID is counted as
  *changed*, and the first version is kept.
- A sync stores rows in batches, and the checkpoint moves only after a batch is stored. A
  failure resumes from the last stored batch. Only one sync of a source runs at a time.
- The mapped columns of every row are kept exactly as read in `org/<key>/capture/*.jsonl`.
  Other columns are never read.
- Snapshots never change after they are made. **Incident numbers restart in each snapshot**:
  INC-00003 in one snapshot is not the same incident as INC-00003 in the next.
- The first 48 hours of a snapshot are the detection baseline, as for every dataset.
- Rows whose order column is empty are never read. Rows committed with an order value older
  than the checkpoint minus the look-back are missed.
- Deleting a source removes its connection and password and stops showing it. The stored data
  stays on disk.
- Snapshots are kept on disk; there is no automatic clean-up yet.
- MySQL, SQL Server and MongoDB are not implemented.

## Verifying against a real server

On a **test** server: `psql ... -f scripts/postgres_test_fixture.sql` (SYNTHETIC rows), set the
reader's password, then set `AGENTSOC_TEST_PG_HOST`, `AGENTSOC_TEST_PG_DATABASE`,
`AGENTSOC_TEST_PG_PASSWORD` (and optionally `_PORT`, `_USER`, `_SSLMODE`) and run
`pytest tests/integration/test_postgres_real.py`.
