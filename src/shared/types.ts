export type Driver = 'postgres' | 'mysql' | 'sqlite'

/** Visual + safety tier for a connection. `production` gates destructive queries. */
export type Environment = 'local' | 'staging' | 'production'

/**
 * Per-connection execution policy. `read-only` is a strict application guard:
 * only plainly read-only SELECTs may execute through any OpenTable surface.
 * Database roles remain the authority for real user/tenant authorization.
 */
export type AccessMode = 'read-write' | 'read-only'

export type ReferentialAction =
  | 'NO ACTION'
  | 'CASCADE'
  | 'SET NULL'
  | 'RESTRICT'
  | 'SET DEFAULT'

export interface SshConfig {
  enabled: boolean
  /** 'agent' authenticates via ssh-agent and ignores password/key fields */
  authMethod?: 'password' | 'key' | 'agent'
  host: string
  port: number
  user: string
  password?: string
  privateKeyPath?: string
  passphrase?: string
}

export interface ConnectionConfig {
  id: string
  name: string
  driver: Driver
  host: string
  port: number
  user: string
  password?: string
  database: string
  /** sqlite only: absolute path to the .db/.sqlite file */
  filePath?: string
  ssl?: boolean
  /** Explicit opt-in: accept self-signed / unverified server certificates */
  sslInsecure?: boolean
  ssh?: SshConfig
  environment?: Environment
  /** Defaults to read-write for existing saved connections. */
  accessMode?: AccessMode
  color?: string
}

/** Config as stored on disk / sent to renderer — password fields stripped or kept encrypted */
export type ConnectionSummary = Omit<ConnectionConfig, 'password' | 'ssh'> & {
  hasPassword: boolean
  ssh?: Omit<SshConfig, 'password' | 'passphrase'>
}

export interface ResultSet {
  columns: string[]
  rows: unknown[][]
  rowCount: number
  command?: string
  /** Present when every column comes from a single table — enables inline editing */
  sourceTable?: { schema: string; name: string }
  /** Column names forming the primary key of sourceTable */
  primaryKey?: string[]
  /** Why inline editing is unavailable, shown quietly in the toolbar */
  readOnlyReason?: string
  truncated?: boolean
}

export interface QueryResult {
  sets: ResultSet[]
  elapsedMs: number
}

export interface SchemaColumn {
  name: string
  /** Exact dialect type when the server exposes it, e.g. varchar(255), numeric(12,2), int unsigned. */
  dataType: string
  nullable: boolean
  isPrimary: boolean
  /** SQL expression suitable for DEFAULT, not a display-only decoded value. */
  defaultValue?: string | null
}

export interface SchemaTable {
  schema: string
  name: string
  kind: 'table' | 'view'
  columns: SchemaColumn[]
}

export interface DbSchema {
  /** Database the schema was read from */
  database: string
  tables: SchemaTable[]
}

export interface IndexInfo {
  name: string
  columns: string[]
  unique: boolean
  primary: boolean
  /** SQLite pragma index_list origin: c=create index, u=UNIQUE constraint, pk=primary key. */
  origin?: string
  /** Raw CREATE INDEX definition when the dialect exposes one. Useful for lossless rebuilds. */
  definition?: string
}

export interface ForeignKeyInfo {
  name: string
  columns: string[]
  refSchema: string
  refTable: string
  refColumns: string[]
  onDelete?: ReferentialAction
  onUpdate?: ReferentialAction
}

export interface TableDetails {
  schema: string
  name: string
  kind: 'table' | 'view'
  columns: SchemaColumn[]
  indexes: IndexInfo[]
  foreignKeys: ForeignKeyInfo[]
  /** Row estimate from metadata. Exact counts are intentionally avoided on large tables. */
  rowCount: number | null
  rowCountApproximate?: boolean
  /** Total table/index storage when the server can report it cheaply. */
  sizeBytes?: number | null
  /** Real primary-key constraint name, needed because PostgreSQL allows custom names. */
  primaryKeyName?: string
  ddl: string
}

export interface ConnectResult {
  ok: boolean
  error?: string
  serverVersion?: string
}

/* ————————————————————— data editing ————————————————————— */

export interface RowIdentity {
  /** primary key column -> original value, used to target the UPDATE/DELETE */
  keys: Record<string, unknown>
}

export type PendingChange =
  | { kind: 'update'; identity: RowIdentity; values: Record<string, unknown> }
  | { kind: 'insert'; values: Record<string, unknown> }
  | { kind: 'delete'; identity: RowIdentity }

export interface ApplyResult {
  ok: boolean
  error?: string
  affected?: number
  /** SQL that was executed, for the review panel / history */
  statements?: string[]
}

/* ————————————————————— history & saved queries ————————————————————— */

export interface HistoryEntry {
  id: string
  connectionId: string
  connectionName: string
  database: string
  sql: string
  ranAt: number
  elapsedMs: number
  rowCount: number
  ok: boolean
  error?: string
}

export interface SavedQuery {
  id: string
  name: string
  sql: string
  connectionId?: string
  updatedAt: number
}

/* ————————————————————— settings & AI ————————————————————— */

/**
 * `anthropic` speaks the Messages API; `openai-compatible` covers everything
 * that implements /v1/chat/completions — Ollama and LM Studio locally, and
 * vLLM, OpenRouter, Groq or NVIDIA NIM remotely.
 */
export type AiProvider = 'anthropic' | 'openai-compatible'

export interface AppSettings {
  /** Rows fetched before OpenTable adds its own LIMIT guard */
  defaultRowLimit: number
  confirmDestructive: boolean
  hasAiKey: boolean
  aiProvider: AiProvider
  /** Empty means the provider's own default endpoint. */
  aiBaseUrl: string
  aiModel: string
}

/* ————————————————————— chat ————————————————————— */

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

/** A query the assistant ran, or wants to run. */
export interface ChatQuery {
  sql: string
  /** false when it needed approval — writes, or anything not plainly read-only */
  autoRun: boolean
  /** why approval was needed, phrased for the prompt */
  reason?: string
  status: 'ran' | 'awaiting-approval' | 'declined' | 'failed'
  columns?: string[]
  rows?: unknown[][]
  rowCount?: number
  error?: string
}

/** One rendered item in a conversation, as opposed to what the model sees. */
export type ChatEntry =
  | { kind: 'you'; text: string }
  | { kind: 'assistant'; text: string }
  | { kind: 'query'; query: ChatQuery }
  | { kind: 'error'; text: string }

export interface ChatSession {
  id: string
  title: string
  /**
   * The connection and database this conversation was held against. A chat is
   * only meaningful next to the schema it was grounded in, so it is never
   * offered anywhere else.
   */
  connectionId: string | null
  connectionName: string
  database: string
  createdAt: number
  updatedAt: number
  entries: ChatEntry[]
  /** the model-facing transcript, including query exchanges */
  transcript: ChatMessage[]
}

export interface ChatTurn {
  /** assistant prose; empty while it is still working through queries */
  reply: string
  /** every query this turn touched, in order, for the audit trail */
  queries: ChatQuery[]
  /** set when the turn stopped to ask permission */
  pending?: ChatQuery
  /**
   * The conversation including the query exchanges, passed back on the next
   * call. Keeping it here rather than in the main process means no session
   * state to leak or expire.
   */
  transcript: ChatMessage[]
  error?: string
}

export interface AiResult {
  ok: boolean
  sql?: string
  explanation?: string
  error?: string
}