import type { AccessMode, Driver } from '../shared/types'
import {
  mainStatementWord,
  maskSqlForAnalysis,
  scanSqlWords,
  splitStatements,
  type SqlWord
} from '../shared/sqlscan'
export { quoteIdent } from '../shared/sql'

/** Renders a value as a SQL literal. Display/logging only — execution uses parameters. */
export function quoteLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL'
  if (typeof value === 'number' || typeof value === 'bigint') return String(value)
  if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE'
  return "'" + String(value).replace(/'/g, "''") + "'"
}

export function placeholder(driver: Driver, index: number): string {
  return driver === 'postgres' ? `$${index}` : '?'
}

export interface BuiltStatement {
  /** parameterized SQL actually sent to the server */
  text: string
  params: unknown[]
  /** human-readable SQL with values inlined, for the review panel and history */
  display: string
}

const WRITE_WORDS = new Set([
  'insert',
  'update',
  'delete',
  'drop',
  'truncate',
  'alter',
  'create',
  'grant',
  'revoke',
  'merge',
  'replace',
  'upsert',
  'rename',
  'copy',
  'call',
  'do'
])

const CTE_WRITE_WORDS = new Set(['insert', 'update', 'delete', 'merge'])

/**
 * A write nested in a WITH body. Looking only inside a leading WITH avoids
 * treating ordinary function/column names in a SELECT as write verbs.
 */
function cteWriteWord(sql: string): SqlWord | undefined {
  const words = scanSqlWords(sql)
  const firstTopLevel = words.find((word) => word.depth === 0)
  if (firstTopLevel?.value !== 'with') return undefined
  return words.find((word) => word.depth > 0 && CTE_WRITE_WORDS.has(word.value))
}

/** True when a statement changes data/structure, including a data-changing CTE. */
export function isDestructive(sql: string): boolean {
  const main = mainStatementWord(sql)
  if (main && WRITE_WORDS.has(main.value)) return true
  return cteWriteWord(sql) !== undefined
}

/** UPDATE/DELETE with no top-level WHERE clause — the classic production accident. */
export function isUnscopedWrite(sql: string): boolean {
  const main = mainStatementWord(sql)
  if (!main || (main.value !== 'update' && main.value !== 'delete')) return false
  return !scanSqlWords(sql).some(
    (word) => word.depth === main.depth && word.start > main.end && word.value === 'where'
  )
}

/* ————————————————————— auto-run classification ————————————————————— */

/**
 * Decides whether the assistant may run a statement on its own, or must stop
 * and ask first. Nothing is permanently forbidden — the user can approve
 * anything they could have typed themselves — but the default is to ask.
 *
 * This is an allowlist, not a blocklist, because the input is model-generated
 * rather than typed by a person. `isDestructive` above is the opposite shape:
 * fine for warning a human about their own SQL, useless as a gate on an LLM.
 *
 * Traps that make a first-keyword check insufficient:
 *   WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x   -- a write, starts WITH
 *   SELECT * INTO new_table FROM t                          -- creates a table (Postgres)
 *   SELECT * FROM t INTO OUTFILE '/tmp/x'                   -- writes a file (MySQL)
 *   SELECT * FROM t FOR UPDATE                              -- takes row locks
 *   SELECT nextval('orders_id_seq')                         -- mutates a sequence
 */
const NEEDS_APPROVAL = [
  // anything that writes data or structure, wherever it appears
  /\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|upsert|rename)\b/i,
  // REPLACE() and MERGE() are also ordinary functions, so only bar them as outer verbs.
  /^\s*(replace|merge)\b/i,
  // procedural escapes
  /\b(call|do|execute|prepare|deallocate)\b/i,
  // server-side file and program access
  /\b(copy|outfile|dumpfile|load_file|lo_import|lo_export|pg_read_file|pg_read_binary_file|pg_ls_dir|dblink)\b/i,
  // session and maintenance verbs
  /\b(set|reset|vacuum|analyze|reindex|cluster|checkpoint|discard|listen|notify|attach|detach)\b/i,
  // SELECT ... INTO creates a table on Postgres
  /\binto\b/i,
  // locking reads
  /\bfor\s+(update|share|no\s+key\s+update|key\s+share)\b/i,
  // functions that mutate server state or can trivially tie up the connection
  /\b(nextval|setval|pg_advisory_lock|pg_advisory_xact_lock|get_lock|release_lock|pg_sleep|sleep|benchmark|generate_series)\s*\(/i
]

export interface AutoRunVerdict {
  /** true when the assistant may run this itself without interrupting */
  autoRun: boolean
  /** why approval is needed, phrased for the confirmation prompt */
  reason?: string
}

/**
 * `statements` comes from splitStatements, which is quote/comment/dollar-quote
 * aware. Anything that is not a single, plainly read-only SELECT needs approval.
 */
export function canAutoRun(statements: string[]): AutoRunVerdict {
  if (statements.length === 0) return { autoRun: false, reason: 'empty statement' }
  if (statements.length > 1) {
    return { autoRun: false, reason: `${statements.length} statements in one block` }
  }

  const original = statements[0]
  const main = mainStatementWord(original)
  if (!main || main.value !== 'select') {
    const verb = main?.value ?? 'statement'
    return { autoRun: false, reason: `${verb.toUpperCase()} changes the database` }
  }

  const nestedWrite = cteWriteWord(original)
  if (nestedWrite) {
    return { autoRun: false, reason: `contains ${nestedWrite.value.toUpperCase()}` }
  }

  const text = maskSqlForAnalysis(original)
  for (const pattern of NEEDS_APPROVAL) {
    const hit = pattern.exec(text)
    if (hit) return { autoRun: false, reason: `contains ${hit[0].trim().toUpperCase()}` }
  }
  return { autoRun: true }
}

export interface AccessModeVerdict {
  allowed: boolean
  reason?: string
}

/**
 * Enforces the connection's execution policy in the trusted main process.
 *
 * Read-only deliberately reuses the AI allowlist instead of maintaining a
 * second, looser parser. That means the guarantee is simple: one plainly
 * read-only SELECT is allowed; anything ambiguous, stateful or multi-statement
 * is blocked before it reaches a driver. This is defense in depth, not a
 * substitute for a least-privilege database role.
 */
export function canRunInAccessMode(
  accessMode: AccessMode | undefined,
  sql: string
): AccessModeVerdict {
  if (accessMode !== 'read-only') return { allowed: true }
  const verdict = canAutoRun(splitStatements(sql))
  if (verdict.autoRun) return { allowed: true }
  return {
    allowed: false,
    reason:
      'This connection is read-only. OpenTable only allows a single plainly read-only SELECT in this mode.'
  }
}