# Operator safety

OpenTable can be used as a lightweight internal admin surface, but network transport, database authorization, and application guardrails solve different problems. This document makes those boundaries explicit.

## The model

| Layer | What it protects | Examples |
| --- | --- | --- |
| Database role | The authority to read or change data | PostgreSQL/MySQL grants, a dedicated least-privilege operator account |
| Network path | How the database is reached | private network, SSH tunnel, verified TLS, provider-internal networking |
| OpenTable access policy | Accidental or model-generated execution inside this app | per-connection **Read only** mode |
| Production safety | Human confirmation before high-risk operations | production connection warnings and destructive-write confirmation |

The database role should remain the final authority. A local application setting is useful defense in depth, not a replacement for server-side permissions.

## Read-only connections

A connection can be marked **Read only** in the connection editor. Existing saved connections remain **Read & write** unless changed explicitly.

Read-only mode is enforced in Electron's main process, before SQL reaches a database driver. It covers every mutation path currently exposed by OpenTable:

- SQL entered in the editor or re-run from history
- inline result-grid edits, inserts, and deletes
- visual schema alteration
- an AI chat write after the user presses the approval button

Read-only query results also have their source-table identity removed before reaching the renderer, so inline editing is not offered in the first place. The main-process check remains the hard stop in case a renderer path is added later or UI state is bypassed.

### Deliberately strict SQL allowlist

Read-only mode reuses the same parser and allowlist used for AI auto-run instead of maintaining a second SQL classifier.

It permits one plainly read-only `SELECT`. It rejects anything ambiguous or stateful, including:

- `INSERT`, `UPDATE`, `DELETE`, DDL and grants
- data-changing CTEs
- `SELECT ... INTO`
- locking reads such as `FOR UPDATE`
- sequence mutation and advisory locks
- multiple statements in one block

This can reject a few statements that a particular database may consider harmless. That is intentional: a connection labelled read-only should fail closed rather than depend on a growing blocklist.

## Connection safety summary

The connection editor shows a small safety summary so transport choices are visible at the point where a connection is configured:

- SQLite is identified as a local database file.
- SSH is identified as a tunnel to the database network.
- TLS distinguishes verified certificates from the explicit self-signed/unverified mode.
- Known loopback/private address literals are described as local/private.
- Unknown hostnames without SSH or TLS receive a conditional warning rather than being falsely labelled public; private DNS names cannot be classified reliably from the client.

For an internal operator, a strong default is a dedicated least-privilege database role plus private/provider networking or SSH/verified TLS, with OpenTable set to **Read only** when the job does not require changes.
