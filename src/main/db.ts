import { createConnection, createServer, type Server, type AddressInfo } from 'net'
import { existsSync, readFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import { DatabaseSync } from 'node:sqlite'
import { Client as SshClient, utils as sshUtils } from 'ssh2'
import mysql from 'mysql2/promise'
import { Client as PgClient } from 'pg'
import type {
  ApplyResult,
  SshConfig,
  ConnectionConfig,
  ConnectResult,
  DbSchema,
  ForeignKeyInfo,
  IndexInfo,
  PendingChange,
  QueryResult,
  ReferentialAction,
  ResultSet,
  SchemaColumn,
  SchemaTable,
  TableDetails
} from '../shared/types'
import { mainStatementWord, scanSqlWords, splitStatements } from '../shared/sqlscan'
import { placeholder, quoteIdent, quoteLiteral, type BuiltStatement } from './sqlutil'
import {
  describeHostKeyFailure,
  verifyKnownHostKey,
  type KnownHostCheck
} from './knownhosts'

export { splitStatements } from '../shared/sqlscan'

interface Tunnel {
  ssh: SshClient
  server: Server
  localPort: number
}

interface Active {
  config: ConnectionConfig
  driver: 'postgres' | 'mysql' | 'sqlite'
  pg?: PgClient
  my?: mysql.Connection
  lite?: DatabaseSync
  tunnel?: Tunnel
  /** backend pid / thread id used to cancel a running statement */
  backendId?: number
  running: boolean
  /** set when the socket died; the next query reconnects rather than failing */
  lost?: boolean
}

const active = new Map<string, Active>()

export type ConnectionState = 'connected' | 'reconnecting' | 'lost'

type StateListener = (id: string, state: ConnectionState, detail?: string) => void
let notifyState: StateListener = () => {}

/** Set by the main process so connection changes reach the window. */
export function onConnectionState(fn: StateListener): void {
  notifyState = fn
}

/**
 * A dropped socket used to delete the connection outright, so the next query
 * said "Not connected" with no way back but restarting the app. Keep the
 * record and its config instead, mark it lost, and let the next query heal it.
 */
function markLost(id: string, detail?: string): void {
  const a = active.get(id)
  if (!a || a.lost) return
  a.lost = true
  notifyState(id, 'lost', detail)
}

// ---------------------------------------------------------------- SSH tunnel

/**
 * Reads the greeting from a TCP port. A real SSH server answers with
 * "SSH-2.0-…" before anything else, so this distinguishes "auth failed" from
 * "that isn't an SSH server at all" — the usual cause of a bare ECONNRESET.
 */
function probeBanner(host: string, port: number, timeoutMs = 4000): Promise<string | null> {
  return new Promise((resolve) => {
    let done = false
    const finish = (value: string | null): void => {
      if (done) return
      done = true
      try {
        socket.destroy()
      } catch {
        /* noop */
      }
      resolve(value)
    }
    const socket = createConnection({ host, port })
    socket.setTimeout(timeoutMs)
    socket.on('data', (buf) => finish(buf.toString('utf-8', 0, 120)))
    socket.on('timeout', () => finish(null))
    socket.on('error', () => finish(null))
    socket.on('close', () => finish(null))
  })
}

/** Names the protocol behind a non-SSH greeting, when it is recognisable. */
function guessProtocol(banner: string): string | null {
  if (/^\x00\x00\x00/.test(banner) || /mysql_native_password|caching_sha2/i.test(banner)) {
    return 'MySQL'
  }
  if (/^HTTP\/|<html/i.test(banner)) return 'an HTTP server'
  if (/^\*|^\+PONG/.test(banner)) return 'Redis'
  if (/PostgreSQL/i.test(banner)) return 'PostgreSQL'
  return null
}

/** `~/…` is what people type; readFileSync needs the real path. */
function expandHome(p: string): string {
  return p.startsWith('~/') ? join(homedir(), p.slice(2)) : p
}

/** Keys ssh(1) would try on its own, so a tunnel works without naming one. */
function defaultKeyPaths(): string[] {
  return ['id_ed25519', 'id_ecdsa', 'id_rsa'].map((f) => join(homedir(), '.ssh', f))
}

interface KeyMaterial {
  /** only set when the key parses with the passphrase we have */
  key?: Buffer
  source: string
  /** parsed, but needs a passphrase we were not given */
  needsPassphrase: boolean
  /** could not be parsed at all */
  parseError?: string
}

/**
 * Whether a key is encrypted cannot be sniffed from the text: an OpenSSH-format
 * key hides its cipher inside base64. ssh2's own parser is the authority.
 */
function loadPrivateKey(explicitPath?: string, passphrase?: string): KeyMaterial {
  const candidates = explicitPath ? [expandHome(explicitPath)] : defaultKeyPaths()

  for (const path of candidates) {
    let raw: Buffer
    try {
      if (!existsSync(path)) continue
      raw = readFileSync(path)
    } catch {
      continue
    }

    const parsed = sshUtils.parseKey(raw, passphrase)
    if (!(parsed instanceof Error)) return { key: raw, source: path, needsPassphrase: false }

    const message = parsed.message || ''
    if (/passphrase|encrypted/i.test(message)) {
      return { source: path, needsPassphrase: true }
    }
    if (explicitPath) return { source: path, needsPassphrase: false, parseError: message }
  }

  if (explicitPath) {
    throw new Error(`Private key not found or unreadable: ${expandHome(explicitPath)}`)
  }
  return { source: 'none', needsPassphrase: false }
}

/** Turns ssh2's terse failures into something a user can act on. */
function describeSshError(
  err: Error,
  tried: string[],
  ssh: SshConfig,
  hostKeyCheck?: KnownHostCheck
): string {
  if (hostKeyCheck && hostKeyCheck.status !== 'trusted') {
    return describeHostKeyFailure(ssh.host, ssh.port || 22, ssh.user, hostKeyCheck)
  }

  const m = err.message || String(err)
  const attempted = tried.length ? ` Tried: ${tried.join(', ')}.` : ''

  if (/All configured authentication methods failed/i.test(m)) {
    return `SSH authentication failed for ${ssh.user}@${ssh.host}.${attempted} Check the username, and that the key is authorised on the server.`
  }
  if (/ECONNRESET/i.test(m)) {
    return `The SSH server at ${ssh.host} closed the connection.${attempted} This usually means it rejected every authentication method — check the username and key, or add your key to the agent with \`ssh-add\`.`
  }
  if (/ECONNREFUSED/i.test(m)) {
    return `Nothing is listening on ${ssh.host}:${ssh.port || 22}. Is SSH running on that port?`
  }
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(m)) {
    return `Cannot resolve the SSH host “${ssh.host}”.`
  }
  if (/ETIMEDOUT|Timed out/i.test(m)) {
    return `Timed out reaching ${ssh.host}:${ssh.port || 22}. A firewall may be blocking it.`
  }
  if (/Cannot parse privateKey|Unsupported key format|bad passphrase|Bad passphrase/i.test(m)) {
    return `Could not read the private key — if it is encrypted, enter its passphrase.`
  }
  if (/Encrypted (OpenSSH )?private key detected|no passphrase given/i.test(m)) {
    return `That private key is encrypted. Enter its passphrase, or add it to your agent with \`ssh-add\`.`
  }
  return `SSH: ${m}${attempted}`
}

async function openTunnel(cfg: ConnectionConfig): Promise<Tunnel> {
  const ssh = cfg.ssh!
  const sshPort = ssh.port || 22

  const banner = await probeBanner(ssh.host, sshPort)
  if (banner && !banner.startsWith('SSH-')) {
    const guess = guessProtocol(banner)
    throw new Error(
      `${ssh.host}:${sshPort} is not an SSH server` +
        (guess ? ` — it looks like ${guess}.` : '.') +
        ' Point the SSH host and port at your bastion (usually port 22), not at the database.'
    )
  }

  return new Promise((resolve, reject) => {
    const tried: string[] = []
    const mode = ssh.authMethod ?? (ssh.privateKeyPath ? 'key' : ssh.password ? 'password' : 'agent')

    let keyMaterial: KeyMaterial = { source: 'none', needsPassphrase: false }
    if (mode === 'key' || (mode !== 'password' && mode !== 'agent')) {
      try {
        keyMaterial = loadPrivateKey(ssh.privateKeyPath, ssh.passphrase)
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)))
        return
      }
    }

    const agentSock = process.env.SSH_AUTH_SOCK
    const usableKey = keyMaterial.key

    if (keyMaterial.parseError) {
      reject(new Error(`Could not read ${keyMaterial.source}: ${keyMaterial.parseError}`))
      return
    }

    if (mode === 'agent' && !agentSock) {
      reject(
        new Error(
          'No SSH agent is running. Start one and add your key with `ssh-add`, or choose a password or private key instead.'
        )
      )
      return
    }

    if (keyMaterial.needsPassphrase && !agentSock) {
      reject(
        new Error(
          `The private key ${keyMaterial.source} is encrypted. Enter its passphrase, or add it to your agent with \`ssh-add\`.`
        )
      )
      return
    }

    if (mode === 'password' && ssh.password) tried.push('password')
    if (usableKey) tried.push(`key (${keyMaterial.source})`)
    if (agentSock) tried.push('ssh-agent')

    if (tried.length === 0) {
      reject(
        new Error(
          `No way to authenticate to ${ssh.host}. Add a password, choose a private key, or run \`ssh-add\` to load a key into your agent.`
        )
      )
      return
    }

    const client = new SshClient()
    let settled = false
    let hostKeyCheck: KnownHostCheck | undefined
    const fail = (err: Error): void => {
      if (settled) return
      settled = true
      try {
        client.end()
      } catch {
        /* noop */
      }
      reject(new Error(describeSshError(err, tried, ssh, hostKeyCheck)))
    }

    client
      .on('ready', () => {
        const server = createServer((socket) => {
          client.forwardOut('127.0.0.1', 0, cfg.host, cfg.port, (err, stream) => {
            if (err) {
              socket.destroy()
              return
            }
            socket.pipe(stream).pipe(socket)
            stream.on('close', () => socket.destroy())
            socket.on('close', () => stream.destroy())
          })
        })
        server.on('error', (err) => fail(err))
        server.listen(0, '127.0.0.1', () => {
          if (settled) return
          settled = true
          const { port } = server.address() as AddressInfo
          resolve({ ssh: client, server, localPort: port })
        })
      })
      .on('keyboard-interactive', (_n, _i, _l, _p, finish) => finish([ssh.password ?? '']))
      .on('error', fail)
      .connect({
        host: ssh.host,
        port: sshPort,
        username: ssh.user,
        // ssh2 calls hostVerifier during key exchange, before user authentication.
        // Fail closed so a password/private key is never sent to an untrusted host.
        hostVerifier: (key: Buffer) => {
          hostKeyCheck = verifyKnownHostKey(ssh.host, sshPort, key)
          return hostKeyCheck.status === 'trusted'
        },
        password: mode === 'password' ? ssh.password || undefined : undefined,
        privateKey: usableKey,
        passphrase: ssh.passphrase || undefined,
        agent: agentSock,
        agentForward: false,
        tryKeyboard: true,
        keepaliveInterval: 20000,
        readyTimeout: 20000
      })
  })
}

function closeTunnel(t?: Tunnel): void {
  try {
    t?.server.close()
    t?.ssh.end()
  } catch {
    /* noop */
  }
}

// ---------------------------------------------------------------- lifecycle

export async function connect(cfg: ConnectionConfig): Promise<ConnectResult> {
  await disconnect(cfg.id)
  let tunnel: Tunnel | undefined
  try {
    if (cfg.driver === 'sqlite') {
      const path = cfg.filePath?.trim()
      if (!path) return { ok: false, error: 'Choose a SQLite database file' }
      const lite = new DatabaseSync(path)
      const v = lite.prepare('select sqlite_version() as v').get() as { v: string }
      active.set(cfg.id, { config: cfg, driver: 'sqlite', lite, running: false })
      startHeartbeat()
      return { ok: true, serverVersion: `SQLite ${v.v}` }
    }

    if (cfg.ssh?.enabled) tunnel = await openTunnel(cfg)
    const host = tunnel ? '127.0.0.1' : cfg.host
    const port = tunnel ? tunnel.localPort : cfg.port

    if (cfg.driver === 'postgres') {
      const pg = new PgClient({
        host,
        port,
        user: cfg.user,
        password: cfg.password || undefined,
        database: cfg.database || 'postgres',
        ssl: cfg.ssl ? { rejectUnauthorized: !cfg.sslInsecure } : undefined,
        connectionTimeoutMillis: 15000,
        // without this an idle session is dropped by NAT, a load balancer or
        // the server's own timeout, with no notice to either end
        keepAlive: true,
        keepAliveInitialDelayMillis: 10_000
      })
      await pg.connect()
      pg.on('error', (err) => markLost(cfg.id, err?.message))
      const v = await pg.query('select version()')
      active.set(cfg.id, {
        config: cfg,
        driver: 'postgres',
        pg,
        tunnel,
        backendId: (pg as unknown as { processID?: number }).processID,
        running: false
      })
      startHeartbeat()
      return { ok: true, serverVersion: String(v.rows[0]?.version ?? '') }
    }

    const my = await mysql.createConnection({
      host,
      port,
      user: cfg.user,
      password: cfg.password || undefined,
      database: cfg.database || undefined,
      multipleStatements: true,
      connectTimeout: 15000,
      ssl: cfg.ssl ? { rejectUnauthorized: !cfg.sslInsecure } : undefined,
      enableKeepAlive: true,
      keepAliveInitialDelay: 10_000
    })
    my.on('error', (err: { message?: string }) => markLost(cfg.id, err?.message))
    const [rows] = await my.query('select version() as v')
    active.set(cfg.id, {
      config: cfg,
      driver: 'mysql',
      my,
      tunnel,
      backendId: (my as unknown as { threadId?: number }).threadId,
      running: false
    })
    startHeartbeat()
    return { ok: true, serverVersion: String((rows as { v: string }[])[0]?.v ?? '') }
  } catch (err) {
    closeTunnel(tunnel)
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

/**
 * Reconnects a session that was marked lost, using the config it was opened
 * with. Called before anything that touches the server, so a dropped socket
 * costs one reconnect rather than a restart of the app.
 */
async function ensureLive(id: string): Promise<void> {
  const a = active.get(id)
  if (!a || !a.lost) return
  notifyState(id, 'reconnecting')
  const res = await connect(a.config)
  if (!res.ok) {
    notifyState(id, 'lost', res.error)
    throw new Error(`Connection lost, and reconnecting failed: ${res.error}`)
  }
  notifyState(id, 'connected')
}

/** Idle sessions are reaped by servers, NAT and load balancers alike. A cheap
 *  round trip keeps them alive and surfaces a death before the user meets it. */
const HEARTBEAT_MS = 30_000
let heartbeat: NodeJS.Timeout | undefined

function startHeartbeat(): void {
  if (heartbeat) return
  heartbeat = setInterval(() => {
    for (const [id, a] of active) {
      // sqlite is a local file, and a busy connection is proof enough of life
      if (a.driver === 'sqlite' || a.running || a.lost) continue
      const ping = a.pg ? a.pg.query('select 1') : a.my?.query('select 1')
      void Promise.resolve(ping).catch((err) =>
        markLost(id, err instanceof Error ? err.message : String(err))
      )
    }
  }, HEARTBEAT_MS)
}

export async function disconnect(id: string): Promise<void> {
  const a = active.get(id)
  if (!a) return
  active.delete(id)
  try {
    await a.pg?.end()
  } catch {
    /* noop */
  }
  try {
    await a.my?.end()
  } catch {
    try {
      a.my?.destroy()
    } catch {
      /* noop */
    }
  }
  try {
    a.lite?.close()
  } catch {
    /* noop */
  }
  closeTunnel(a.tunnel)
}

export async function disconnectAll(): Promise<void> {
  if (heartbeat) {
    clearInterval(heartbeat)
    heartbeat = undefined
  }
  await Promise.all([...active.keys()].map((id) => disconnect(id)))
}

export async function testConnection(cfg: ConnectionConfig): Promise<ConnectResult> {
  const tempId = `__test__${Date.now()}`
  const res = await connect({ ...cfg, id: tempId })
  await disconnect(tempId)
  return res
}

export function getConfig(id: string): ConnectionConfig | undefined {
  return active.get(id)?.config
}

// ---------------------------------------------------------------- cancellation

export async function cancelQuery(id: string): Promise<{ ok: boolean; error?: string }> {
  const a = active.get(id)
  if (!a) return { ok: false, error: 'Not connected' }
  if (!a.running) return { ok: true }

  try {
    if (a.driver === 'sqlite') {
      return { ok: false, error: 'SQLite queries cannot be cancelled' }
    }

    const cfg = a.config
    const host = a.tunnel ? '127.0.0.1' : cfg.host
    const port = a.tunnel ? a.tunnel.localPort : cfg.port

    if (a.driver === 'postgres') {
      if (!a.backendId) return { ok: false, error: 'No backend pid' }
      const killer = new PgClient({
        host,
        port,
        user: cfg.user,
        password: cfg.password || undefined,
        database: cfg.database || 'postgres',
        ssl: cfg.ssl ? { rejectUnauthorized: !cfg.sslInsecure } : undefined,
        connectionTimeoutMillis: 8000
      })
      await killer.connect()
      await killer.query('select pg_cancel_backend($1)', [a.backendId])
      await killer.end()
      return { ok: true }
    }

    if (!a.backendId) return { ok: false, error: 'No thread id' }
    const killer = await mysql.createConnection({
      host,
      port,
      user: cfg.user,
      password: cfg.password || undefined,
      connectTimeout: 8000,
      ssl: cfg.ssl ? { rejectUnauthorized: !cfg.sslInsecure } : undefined
    })
    await killer.query(`KILL QUERY ${Number(a.backendId)}`)
    await killer.end()
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

// ---------------------------------------------------------------- queries

function normalizeValue(v: unknown): unknown {
  if (v === null || v === undefined) return null
  if (v instanceof Date) return v.toISOString()
  if (Buffer.isBuffer(v)) return `0x${v.toString('hex').slice(0, 512)}`
  if (typeof v === 'bigint') return v.toString()
  if (typeof v === 'object') return JSON.stringify(v)
  return v
}

function pgResultToSet(r: {
  fields?: { name: string }[]
  rows?: unknown[][]
  rowCount?: number | null
  command?: string
}): ResultSet {
  const columns = (r.fields ?? []).map((f) => f.name)
  const rows = (r.rows ?? []).map((row) => row.map(normalizeValue))
  return { columns, rows, rowCount: r.rowCount ?? rows.length, command: r.command }
}

function mysqlToSet(rows: unknown, fields: mysql.FieldPacket[] | undefined): ResultSet {
  if (Array.isArray(rows) && fields && fields.length) {
    return {
      columns: fields.map((f) => f.name),
      rows: (rows as unknown[][]).map((row) => row.map(normalizeValue)),
      rowCount: rows.length
    }
  }
  const header = rows as { affectedRows?: number } | undefined
  return { columns: [], rows: [], rowCount: header?.affectedRows ?? 0, command: 'OK' }
}

function isSelectLike(sql: string): boolean {
  return /^\s*(select|with|show|describe|desc|explain|pragma|table|values)\b/i.test(sql)
}

/** Only a LIMIT/FETCH at the outer statement depth counts as a user supplied guard. */
function hasTopLevelLimit(sql: string): boolean {
  const main = mainStatementWord(sql)
  if (!main || main.value !== 'select') return false
  return scanSqlWords(sql).some(
    (word) =>
      word.depth === main.depth &&
      word.start > main.end &&
      (word.value === 'limit' || word.value === 'fetch')
  )
}

/**
 * Adds a LIMIT to a plain outer SELECT without corrupting OFFSET/FETCH/FOR UPDATE
 * clause order. Nested subquery limits do not disable the guard.
 */
function applyRowLimit(sql: string, limit: number): { sql: string; guarded: boolean } {
  const trimmed = sql.trim().replace(/;\s*$/, '')
  if (limit <= 0) return { sql: trimmed, guarded: false }
  const main = mainStatementWord(trimmed)
  if (!main || main.value !== 'select' || hasTopLevelLimit(trimmed)) {
    return { sql: trimmed, guarded: false }
  }

  const boundary = scanSqlWords(trimmed)
    .filter(
      (word) =>
        word.depth === main.depth &&
        word.start > main.end &&
        (word.value === 'offset' || word.value === 'fetch' || word.value === 'for')
    )
    .sort((a, b) => a.start - b.start)[0]

  if (!boundary) return { sql: `${trimmed}\nLIMIT ${limit}`, guarded: true }
  const before = trimmed.slice(0, boundary.start).trimEnd()
  const after = trimmed.slice(boundary.start).trimStart()
  return { sql: `${before}\nLIMIT ${limit}\n${after}`, guarded: true }
}

/** Detect a single-table SELECT so the grid can offer inline editing. */
type SourceProbe =
  | { ok: true; schema: string; name: string; pk: string[] }
  | { ok: false; reason: string }

async function detectSource(id: string, sql: string): Promise<SourceProbe> {
  if (/\bjoin\b/i.test(sql) || /\bfrom\s*\(/i.test(sql) || /\bunion\b/i.test(sql)) {
    return { ok: false, reason: 'joined query' }
  }
  if (/\bgroup\s+by\b/i.test(sql) || /\bdistinct\b/i.test(sql)) {
    return { ok: false, reason: 'aggregated query' }
  }

  const m = /\bfrom\s+([`"[]?[\w.$]+[`"\]]?(?:\s*\.\s*[`"[]?[\w$]+[`"\]]?)?)/i.exec(sql)
  if (!m) return { ok: false, reason: 'no single table' }

  const raw = m[1].replace(/[`"[\]]/g, '')
  const parts = raw.split('.').map((p) => p.trim())
  const table = parts[parts.length - 1]
  const schemaName = parts.length > 1 ? parts[parts.length - 2] : ''

  const schema = await getSchema(id)
  const hit = schema.tables.find(
    (t) => t.name.toLowerCase() === table.toLowerCase() && (!schemaName || t.schema === schemaName)
  )
  if (!hit) return { ok: false, reason: 'unknown table' }
  if (hit.kind !== 'table') return { ok: false, reason: 'view' }

  const pk = hit.columns.filter((c) => c.isPrimary).map((c) => c.name)
  if (pk.length === 0) return { ok: false, reason: 'no primary key' }
  return { ok: true, schema: hit.schema, name: hit.name, pk }
}

export async function runQuery(
  id: string,
  sql: string,
  opts: { rowLimit?: number } = {}
): Promise<QueryResult> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) throw new Error('Not connected')
  const limit = opts.rowLimit ?? 0
  const started = performance.now()
  a.running = true

  try {
    const statements = splitStatements(sql)
    const sets: ResultSet[] = []

    for (const raw of statements) {
      const { sql: guardedSql, guarded } = applyRowLimit(raw, limit)

      if (a.driver === 'sqlite') {
        const lite = a.lite!
        if (isSelectLike(guardedSql)) {
          const stmt = lite.prepare(guardedSql)
          stmt.setReadBigInts(false)
          const rows = stmt.all() as Record<string, unknown>[]
          const columns = rows.length ? Object.keys(rows[0]) : readSqliteColumns(lite, guardedSql)
          sets.push({
            columns,
            rows: rows.map((r) => columns.map((c) => normalizeValue(r[c]))),
            rowCount: rows.length,
            truncated: guarded && rows.length >= limit
          })
        } else {
          const info = lite.prepare(guardedSql).run()
          sets.push({
            columns: [],
            rows: [],
            rowCount: Number(info.changes ?? 0),
            command: 'OK'
          })
        }
        continue
      }

      if (a.driver === 'postgres') {
        const result = await a.pg!.query({ text: guardedSql, rowMode: 'array' } as never)
        const list = Array.isArray(result) ? result : [result]
        for (const r of list) {
          const set = pgResultToSet(r as never)
          set.truncated = guarded && set.rows.length >= limit
          sets.push(set)
        }
        continue
      }

      const [rows, fields] = await a.my!.query({ sql: guardedSql, rowsAsArray: true })
      const multi = Array.isArray(fields) && fields.length > 0 && Array.isArray(fields[0])
      const produced = multi
        ? (rows as unknown[]).map((r, i) =>
            mysqlToSet(r, (fields as unknown as mysql.FieldPacket[][])[i])
          )
        : [mysqlToSet(rows, fields as mysql.FieldPacket[] | undefined)]
      for (const set of produced) {
        set.truncated = guarded && set.rows.length >= limit
        sets.push(set)
      }
    }

    if (sets.length === 1 && sets[0].columns.length && statements.length === 1) {
      try {
        const src = await detectSource(id, statements[0])
        if (!src.ok) {
          sets[0].readOnlyReason = src.reason
        } else if (!src.pk.every((k) => sets[0].columns.includes(k))) {
          sets[0].readOnlyReason = 'primary key not selected'
        } else {
          sets[0].sourceTable = { schema: src.schema, name: src.name }
          sets[0].primaryKey = src.pk
        }
      } catch {
        /* editing metadata is best-effort */
      }
    }

    return { sets, elapsedMs: performance.now() - started }
  } finally {
    a.running = false
  }
}

function readSqliteColumns(lite: DatabaseSync, sql: string): string[] {
  try {
    const stmt = lite.prepare(sql)
    const cols = (stmt as unknown as { columns?: () => { name: string }[] }).columns?.()
    return cols ? cols.map((c) => c.name) : []
  } catch {
    return []
  }
}

// ---------------------------------------------------------------- schema

function schemaKey(schema: string, table: string): string {
  return `${schema}\u0000${table}`
}

function pushColumn(map: Map<string, SchemaColumn[]>, key: string, column: SchemaColumn): void {
  const list = map.get(key) ?? []
  list.push(column)
  map.set(key, list)
}

function mysqlColumnType(row: {
  ct: string
  ex: string
  gen: string | null
}): string {
  let type = row.ct || 'text'
  if (/auto_increment/i.test(row.ex) && !/auto_increment/i.test(type)) type += ' AUTO_INCREMENT'
  if (row.gen) {
    type += ` GENERATED ALWAYS AS (${row.gen}) ${/stored/i.test(row.ex) ? 'STORED' : 'VIRTUAL'}`
  }
  return type
}

function mysqlDefaultSql(value: unknown, type: string, extra: string): string | null {
  if (value === null || value === undefined) return null
  const raw = String(value)
  if (/^(tinyint|smallint|mediumint|int|integer|bigint|decimal|numeric|float|double|real|bit|year)\b/i.test(type)) {
    return raw
  }
  if (/^(CURRENT_TIMESTAMP(?:\(\d+\))?|CURRENT_DATE|CURRENT_TIME|LOCALTIME(?:\(\d+\))?|LOCALTIMESTAMP(?:\(\d+\))?|NULL)$/i.test(raw)) {
    return raw
  }
  if (/DEFAULT_GENERATED/i.test(extra) && /^\(.+\)$/s.test(raw)) return raw
  return quoteLiteral(raw)
}

export async function getSchema(id: string): Promise<DbSchema> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) throw new Error('Not connected')

  if (a.driver === 'sqlite') {
    const lite = a.lite!
    const rows = lite
      .prepare(
        `select m.name as table_name, m.type as table_type,
                p.cid as cid, p.name as column_name, p.type as data_type,
                p."notnull" as not_null, p.dflt_value as default_value, p.pk as pk
           from sqlite_schema m
           left join pragma_table_info(m.name) p
          where m.type in ('table','view') and m.name not like 'sqlite_%'
          order by m.name, p.cid`
      )
      .all() as {
      table_name: string
      table_type: string
      cid: number | null
      column_name: string | null
      data_type: string | null
      not_null: number | null
      default_value: string | null
      pk: number | null
    }[]

    const tableMap = new Map<string, SchemaTable>()
    for (const r of rows) {
      let table = tableMap.get(r.table_name)
      if (!table) {
        table = {
          schema: 'main',
          name: r.table_name,
          kind: r.table_type === 'view' ? 'view' : 'table',
          columns: []
        }
        tableMap.set(r.table_name, table)
      }
      if (r.column_name) {
        table.columns.push({
          name: r.column_name,
          dataType: r.data_type || 'BLOB',
          nullable: r.not_null === 0,
          isPrimary: Number(r.pk ?? 0) > 0,
          defaultValue: r.default_value
        })
      }
    }
    return {
      database: a.config.filePath?.split('/').pop() ?? 'sqlite',
      tables: [...tableMap.values()]
    }
  }

  if (a.driver === 'postgres') {
    const [dbRes, tablesRes, colsRes] = await Promise.all([
      a.pg!.query('select current_database() as db'),
      a.pg!.query(
        `select table_schema, table_name, table_type
           from information_schema.tables
          where table_schema not in ('pg_catalog','information_schema')
          order by table_schema, table_name`
      ),
      a.pg!.query(
        `select ic.table_schema, ic.table_name, ic.column_name,
                pg_catalog.format_type(att.atttypid, att.atttypmod) as data_type,
                ic.is_nullable, ic.column_default,
                exists (
                  select 1
                    from pg_index pix
                   where pix.indrelid = cls.oid
                     and pix.indisprimary
                     and att.attnum = any(pix.indkey)
                ) as is_primary
           from information_schema.columns ic
           join pg_namespace ns on ns.nspname = ic.table_schema
           join pg_class cls on cls.relnamespace = ns.oid and cls.relname = ic.table_name
           join pg_attribute att
             on att.attrelid = cls.oid
            and att.attname = ic.column_name
            and att.attnum > 0
            and not att.attisdropped
          where ic.table_schema not in ('pg_catalog','information_schema')
          order by ic.table_schema, ic.table_name, ic.ordinal_position`
      )
    ])
    const database = String(dbRes.rows[0]?.db ?? '')
    const grouped = new Map<string, SchemaColumn[]>()
    for (const c of colsRes.rows) {
      pushColumn(grouped, schemaKey(c.table_schema, c.table_name), {
        name: c.column_name,
        dataType: String(c.data_type ?? 'text'),
        nullable: c.is_nullable === 'YES',
        isPrimary: Boolean(c.is_primary),
        defaultValue: c.column_default
      })
    }
    const tables: SchemaTable[] = tablesRes.rows.map((t) => ({
      schema: t.table_schema,
      name: t.table_name,
      kind: t.table_type === 'VIEW' ? 'view' : 'table',
      columns: grouped.get(schemaKey(t.table_schema, t.table_name)) ?? []
    }))
    return { database, tables }
  }

  const [[dbRows], [tRows], [cRows]] = await Promise.all([
    a.my!.query('select database() as db'),
    a.my!.query(
      `select table_schema as ts, table_name as tn, table_type as tt
         from information_schema.tables
        where table_schema = database()
        order by table_name`
    ),
    a.my!.query(
      `select table_schema as ts, table_name as tn, column_name as cn,
              column_type as ct, is_nullable as nl, column_key as ck,
              column_default as cd, extra as ex, generation_expression as gen
         from information_schema.columns
        where table_schema = database()
        order by table_name, ordinal_position`
    )
  ])
  const database = String((dbRows as { db: string | null }[])[0]?.db ?? '')
  const grouped = new Map<string, SchemaColumn[]>()
  for (const c of cRows as {
    ts: string
    tn: string
    cn: string
    ct: string
    nl: string
    ck: string
    cd: unknown
    ex: string
    gen: string | null
  }[]) {
    const type = mysqlColumnType(c)
    pushColumn(grouped, schemaKey(c.ts, c.tn), {
      name: c.cn,
      dataType: type,
      nullable: c.nl === 'YES',
      isPrimary: c.ck === 'PRI',
      defaultValue: mysqlDefaultSql(c.cd, c.ct, c.ex)
    })
  }
  const tables: SchemaTable[] = (tRows as { ts: string; tn: string; tt: string }[]).map((t) => ({
    schema: t.ts,
    name: t.tn,
    kind: t.tt === 'VIEW' ? 'view' : 'table',
    columns: grouped.get(schemaKey(t.ts, t.tn)) ?? []
  }))
  return { database, tables }
}

/** node-postgres does not parse every array type — accept a raw `{a,b}` literal too. */
function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v) => v != null).map(String)
  if (typeof value === 'string' && value.startsWith('{') && value.endsWith('}')) {
    return value
      .slice(1, -1)
      .split(',')
      .map((v) => v.trim().replace(/^"|"$/g, ''))
      .filter(Boolean)
  }
  return []
}

const REFERENTIAL_ACTIONS = new Set<ReferentialAction>([
  'NO ACTION',
  'CASCADE',
  'SET NULL',
  'RESTRICT',
  'SET DEFAULT'
])

function normalizeAction(value: unknown): ReferentialAction | undefined {
  if (value == null) return undefined
  const action = String(value).trim().replace(/\s+/g, ' ').toUpperCase() as ReferentialAction
  return REFERENTIAL_ACTIONS.has(action) ? action : undefined
}

function postgresAction(value: unknown): ReferentialAction | undefined {
  const action = ({
    a: 'NO ACTION',
    r: 'RESTRICT',
    c: 'CASCADE',
    n: 'SET NULL',
    d: 'SET DEFAULT'
  } as Record<string, ReferentialAction>)[String(value ?? '')]
  return action
}

// ---------------------------------------------------------------- table details

export async function getTableDetails(
  id: string,
  schemaName: string,
  table: string
): Promise<TableDetails> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) throw new Error('Not connected')
  const schema = await getSchema(id)
  const hit = schema.tables.find(
    (t) => t.name === table && (!schemaName || t.schema === schemaName)
  )
  if (!hit) throw new Error(`Table ${table} not found`)

  const indexes: IndexInfo[] = []
  const foreignKeys: ForeignKeyInfo[] = []
  let ddl = ''
  let rowCount: number | null = null
  let rowCountApproximate = false
  let sizeBytes: number | null = null
  let primaryKeyName: string | undefined

  const qualified =
    a.driver === 'mysql' || a.driver === 'sqlite'
      ? quoteIdent(table, a.driver)
      : `${quoteIdent(hit.schema, 'postgres')}.${quoteIdent(table, 'postgres')}`

  try {
    if (a.driver === 'sqlite') {
      const lite = a.lite!
      const idx = lite.prepare(`pragma index_list(${quoteIdent(table, 'sqlite')})`).all() as {
        name: string
        unique: number
        origin: string
      }[]
      for (const ix of idx) {
        const cols = lite.prepare(`pragma index_info(${quoteIdent(ix.name, 'sqlite')})`).all() as {
          name: string | null
        }[]
        const def = lite
          .prepare(`select sql from sqlite_schema where type = 'index' and name = ?`)
          .get(ix.name) as { sql?: string | null } | undefined
        indexes.push({
          name: ix.name,
          columns: cols.map((c) => c.name).filter((c): c is string => Boolean(c)),
          unique: ix.unique === 1,
          primary: ix.origin === 'pk',
          origin: ix.origin,
          definition: def?.sql ?? undefined
        })
      }
      primaryKeyName = indexes.find((ix) => ix.primary)?.name

      const fkRows = lite.prepare(`pragma foreign_key_list(${quoteIdent(table, 'sqlite')})`).all() as {
        id: number
        seq: number
        table: string
        from: string
        to: string
        on_update: string
        on_delete: string
      }[]
      const fkGroups = new Map<number, ForeignKeyInfo & { seqs: number[] }>()
      for (const fk of fkRows) {
        const group = fkGroups.get(fk.id) ?? {
          name: `fk_${fk.id}`,
          columns: [],
          refSchema: 'main',
          refTable: fk.table,
          refColumns: [],
          onUpdate: normalizeAction(fk.on_update),
          onDelete: normalizeAction(fk.on_delete),
          seqs: []
        }
        group.columns.push(fk.from)
        group.refColumns.push(fk.to)
        group.seqs.push(fk.seq)
        fkGroups.set(fk.id, group)
      }
      for (const group of fkGroups.values()) {
        const zipped = group.columns.map((column, i) => ({
          column,
          ref: group.refColumns[i],
          seq: group.seqs[i]
        }))
        zipped.sort((x, y) => x.seq - y.seq)
        const { seqs: _seqs, ...info } = group
        info.columns = zipped.map((x) => x.column)
        info.refColumns = zipped.map((x) => x.ref)
        foreignKeys.push(info)
      }

      const row = lite
        .prepare(`select sql from sqlite_schema where type in ('table','view') and name = ?`)
        .get(table) as { sql?: string } | undefined
      ddl = row?.sql ?? ''

      // sqlite_stat1 is populated by ANALYZE. When present it gives a cheap row
      // estimate; when absent we show no count rather than freezing on COUNT(*).
      const statTable = lite
        .prepare(`select 1 as ok from sqlite_schema where type = 'table' and name = 'sqlite_stat1'`)
        .get() as { ok?: number } | undefined
      if (statTable) {
        const stats = lite.prepare(`select stat from sqlite_stat1 where tbl = ?`).all(table) as {
          stat: string
        }[]
        const estimates = stats
          .map((s) => Number(/^\s*(\d+)/.exec(s.stat)?.[1] ?? NaN))
          .filter(Number.isFinite)
        if (estimates.length) {
          rowCount = Math.max(...estimates)
          rowCountApproximate = true
        }
      }
    } else if (a.driver === 'postgres') {
      const [idx, fk, meta] = await Promise.all([
        a.pg!.query(
          `select i.relname as name, ix.indisunique as uniq, ix.indisprimary as prim,
                  pg_get_indexdef(ix.indexrelid) as definition,
                  array(
                    select pg_get_indexdef(ix.indexrelid, k + 1, true)
                      from generate_subscripts(ix.indkey, 1) as k
                     order by k
                  ) as cols
             from pg_index ix
             join pg_class i on i.oid = ix.indexrelid
             join pg_class t on t.oid = ix.indrelid
             join pg_namespace n on n.oid = t.relnamespace
            where t.relname = $1 and n.nspname = $2
            order by ix.indisprimary desc, i.relname`,
          [table, hit.schema]
        ),
        a.pg!.query(
          `select con.conname as name,
                  nf.nspname as ref_schema, cf.relname as ref_table,
                  con.confupdtype::text as update_rule,
                  con.confdeltype::text as delete_rule,
                  (select array_agg(att.attname::text order by u.ord)
                     from unnest(con.conkey) with ordinality as u(attnum, ord)
                     join pg_attribute att
                       on att.attrelid = con.conrelid and att.attnum = u.attnum) as cols,
                  (select array_agg(att.attname::text order by u.ord)
                     from unnest(con.confkey) with ordinality as u(attnum, ord)
                     join pg_attribute att
                       on att.attrelid = con.confrelid and att.attnum = u.attnum) as ref_cols
             from pg_constraint con
             join pg_class c on c.oid = con.conrelid
             join pg_namespace n on n.oid = c.relnamespace
             join pg_class cf on cf.oid = con.confrelid
             join pg_namespace nf on nf.oid = cf.relnamespace
            where con.contype = 'f' and c.relname = $1 and n.nspname = $2
            order by con.conname`,
          [table, hit.schema]
        ),
        a.pg!.query(
          `select case when c.reltuples < 0 then null else c.reltuples::bigint end as estimated_rows,
                  pg_total_relation_size(c.oid)::bigint as size_bytes,
                  (select pc.conname
                     from pg_constraint pc
                    where pc.conrelid = c.oid and pc.contype = 'p'
                    limit 1) as primary_key_name
             from pg_class c
             join pg_namespace n on n.oid = c.relnamespace
            where c.relname = $1 and n.nspname = $2
            limit 1`,
          [table, hit.schema]
        )
      ])

      for (const r of idx.rows) {
        indexes.push({
          name: String(r.name),
          columns: toStringArray(r.cols),
          unique: Boolean(r.uniq),
          primary: Boolean(r.prim),
          definition: r.definition ? String(r.definition) : undefined
        })
      }
      for (const r of fk.rows) {
        foreignKeys.push({
          name: String(r.name),
          columns: toStringArray(r.cols),
          refSchema: String(r.ref_schema ?? ''),
          refTable: String(r.ref_table ?? ''),
          refColumns: toStringArray(r.ref_cols),
          onUpdate: postgresAction(r.update_rule),
          onDelete: postgresAction(r.delete_rule)
        })
      }
      const m = meta.rows[0]
      if (m?.estimated_rows != null) {
        rowCount = Number(m.estimated_rows)
        rowCountApproximate = true
      }
      if (m?.size_bytes != null) sizeBytes = Number(m.size_bytes)
      primaryKeyName = m?.primary_key_name ? String(m.primary_key_name) : undefined
      ddl = buildDdlFromColumns(hit, 'postgres')
    } else {
      const [idxRows, fkRows, createdRows, metaRows] = await Promise.all([
        a.my!.query(`show index from ${qualified}`),
        a.my!.query(
          `select k.constraint_name as name, k.column_name as col,
                  k.referenced_table_schema as rs, k.referenced_table_name as rt,
                  k.referenced_column_name as rc, k.ordinal_position as ord,
                  r.update_rule as update_rule, r.delete_rule as delete_rule
             from information_schema.key_column_usage k
             left join information_schema.referential_constraints r
               on r.constraint_schema = k.constraint_schema
              and r.constraint_name = k.constraint_name
              and r.table_name = k.table_name
            where k.table_schema = database() and k.table_name = ?
              and k.referenced_table_name is not null
            order by k.constraint_name, k.ordinal_position`,
          [table]
        ),
        a.my!.query(`show create table ${qualified}`),
        a.my!.query(
          `select table_rows as estimated_rows,
                  coalesce(data_length, 0) + coalesce(index_length, 0) as size_bytes
             from information_schema.tables
            where table_schema = database() and table_name = ?`,
          [table]
        )
      ])

      const idx = idxRows[0] as {
        Key_name: string
        Column_name: string | null
        Non_unique: number
        Seq_in_index: number
      }[]
      const grouped = new Map<string, { cols: { name: string; seq: number }[]; unique: boolean }>()
      for (const r of idx) {
        const g = grouped.get(r.Key_name) ?? { cols: [], unique: r.Non_unique === 0 }
        if (r.Column_name) g.cols.push({ name: r.Column_name, seq: Number(r.Seq_in_index) })
        grouped.set(r.Key_name, g)
      }
      for (const [name, g] of grouped) {
        g.cols.sort((x, y) => x.seq - y.seq)
        indexes.push({
          name,
          columns: g.cols.map((x) => x.name),
          unique: g.unique,
          primary: name === 'PRIMARY'
        })
      }
      if (indexes.some((ix) => ix.primary)) primaryKeyName = 'PRIMARY'

      const fkGroups = new Map<string, ForeignKeyInfo & { ordinals: number[] }>()
      for (const r of fkRows[0] as {
        name: string
        col: string
        rs: string
        rt: string
        rc: string
        ord: number
        update_rule: string
        delete_rule: string
      }[]) {
        const g = fkGroups.get(r.name) ?? {
          name: r.name,
          columns: [],
          refSchema: r.rs,
          refTable: r.rt,
          refColumns: [],
          onUpdate: normalizeAction(r.update_rule),
          onDelete: normalizeAction(r.delete_rule),
          ordinals: []
        }
        g.columns.push(r.col)
        g.refColumns.push(r.rc)
        g.ordinals.push(Number(r.ord))
        fkGroups.set(r.name, g)
      }
      for (const group of fkGroups.values()) {
        const zipped = group.columns.map((column, i) => ({
          column,
          ref: group.refColumns[i],
          ordinal: group.ordinals[i]
        }))
        zipped.sort((x, y) => x.ordinal - y.ordinal)
        const { ordinals: _ordinals, ...info } = group
        info.columns = zipped.map((x) => x.column)
        info.refColumns = zipped.map((x) => x.ref)
        foreignKeys.push(info)
      }

      const created = createdRows[0] as Record<string, string>[]
      ddl = created[0]?.['Create Table'] ?? ''
      const meta = (metaRows[0] as {
        estimated_rows: number | string | null
        size_bytes: number | string | null
      }[])[0]
      if (meta?.estimated_rows != null) {
        rowCount = Number(meta.estimated_rows)
        rowCountApproximate = true
      }
      if (meta?.size_bytes != null) sizeBytes = Number(meta.size_bytes)
    }
  } catch {
    /* details are best-effort; return whatever we gathered */
  }

  if (!ddl) ddl = buildDdlFromColumns(hit, a.driver)

  return {
    schema: hit.schema,
    name: hit.name,
    kind: hit.kind,
    columns: hit.columns,
    indexes,
    foreignKeys,
    rowCount,
    rowCountApproximate,
    sizeBytes,
    primaryKeyName,
    ddl
  }
}

function buildDdlFromColumns(t: SchemaTable, driver: 'postgres' | 'mysql' | 'sqlite'): string {
  const lines = t.columns.map((c) => {
    const bits = [quoteIdent(c.name, driver), c.dataType]
    if (!c.nullable) bits.push('NOT NULL')
    if (c.defaultValue) bits.push(`DEFAULT ${c.defaultValue}`)
    return '  ' + bits.join(' ')
  })
  const pk = t.columns.filter((c) => c.isPrimary).map((c) => quoteIdent(c.name, driver))
  if (pk.length) lines.push(`  PRIMARY KEY (${pk.join(', ')})`)
  return `CREATE TABLE ${quoteIdent(t.name, driver)} (\n${lines.join(',\n')}\n);`
}

// ---------------------------------------------------------------- editing

export async function applyChanges(
  id: string,
  table: { schema: string; name: string },
  changes: PendingChange[]
): Promise<ApplyResult> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) return { ok: false, error: 'Not connected' }
  if (changes.length === 0) return { ok: true, affected: 0, statements: [] }

  const driver = a.driver
  const qualified =
    driver === 'postgres'
      ? `${quoteIdent(table.schema, 'postgres')}.${quoteIdent(table.name, 'postgres')}`
      : quoteIdent(table.name, driver)

  const built: BuiltStatement[] = []
  for (const ch of changes) {
    const params: unknown[] = []
    const ph = (): string => placeholder(driver, params.length)

    if (ch.kind === 'update') {
      const setCols = Object.keys(ch.values)
      if (setCols.length === 0) continue
      const sets = setCols
        .map((col) => {
          params.push(ch.values[col])
          return `${quoteIdent(col, driver)} = ${ph()}`
        })
        .join(', ')
      const keyCols = Object.keys(ch.identity.keys)
      const where = keyCols
        .map((col) => {
          params.push(ch.identity.keys[col])
          return `${quoteIdent(col, driver)} = ${ph()}`
        })
        .join(' AND ')
      built.push({
        text: `UPDATE ${qualified} SET ${sets} WHERE ${where}`,
        params,
        display:
          `UPDATE ${qualified} SET ` +
          setCols.map((c) => `${quoteIdent(c, driver)} = ${quoteLiteral(ch.values[c])}`).join(', ') +
          ' WHERE ' +
          keyCols
            .map((c) => `${quoteIdent(c, driver)} = ${quoteLiteral(ch.identity.keys[c])}`)
            .join(' AND ') +
          ';'
      })
    } else if (ch.kind === 'insert') {
      const cols = Object.keys(ch.values)
      if (cols.length === 0) continue
      const names = cols.map((c) => quoteIdent(c, driver)).join(', ')
      const marks = cols
        .map((c) => {
          params.push(ch.values[c])
          return ph()
        })
        .join(', ')
      built.push({
        text: `INSERT INTO ${qualified} (${names}) VALUES (${marks})`,
        params,
        display: `INSERT INTO ${qualified} (${names}) VALUES (${cols
          .map((c) => quoteLiteral(ch.values[c]))
          .join(', ')});`
      })
    } else {
      const keyCols = Object.keys(ch.identity.keys)
      if (keyCols.length === 0) continue
      const where = keyCols
        .map((col) => {
          params.push(ch.identity.keys[col])
          return `${quoteIdent(col, driver)} = ${ph()}`
        })
        .join(' AND ')
      built.push({
        text: `DELETE FROM ${qualified} WHERE ${where}`,
        params,
        display:
          `DELETE FROM ${qualified} WHERE ` +
          keyCols
            .map((c) => `${quoteIdent(c, driver)} = ${quoteLiteral(ch.identity.keys[c])}`)
            .join(' AND ') +
          ';'
      })
    }
  }

  const statements = built.map((b) => b.display)

  try {
    let affected = 0
    if (driver === 'sqlite') {
      const lite = a.lite!
      lite.exec('BEGIN')
      try {
        for (const b of built) {
          affected += Number(lite.prepare(b.text).run(...(b.params as never[])).changes ?? 0)
        }
        lite.exec('COMMIT')
      } catch (e) {
        lite.exec('ROLLBACK')
        throw e
      }
    } else if (driver === 'postgres') {
      const pg = a.pg!
      await pg.query('BEGIN')
      try {
        for (const b of built) {
          const r = await pg.query(b.text, b.params)
          affected += r.rowCount ?? 0
        }
        await pg.query('COMMIT')
      } catch (e) {
        await pg.query('ROLLBACK')
        throw e
      }
    } else {
      const my = a.my!
      await my.beginTransaction()
      try {
        for (const b of built) {
          const [r] = await my.execute({ sql: b.text, values: b.params })
          affected += (r as { affectedRows?: number }).affectedRows ?? 0
        }
        await my.commit()
      } catch (e) {
        await my.rollback()
        throw e
      }
    }
    return { ok: true, affected, statements }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      statements
    }
  }
}

export async function applyAlter(
  id: string,
  statements: string[]
): Promise<{ ok: boolean; error?: string; applied: number }> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) return { ok: false, error: 'Not connected', applied: 0 }
  if (statements.length === 0) return { ok: true, applied: 0 }

  let applied = 0
  try {
    if (a.driver === 'sqlite') {
      const lite = a.lite!
      const selfManaged = statements.some((s) => /^\s*BEGIN/i.test(s))
      if (!selfManaged) lite.exec('BEGIN')
      try {
        for (const sql of statements) {
          lite.exec(sql)
          applied++
        }
        if (!selfManaged) lite.exec('COMMIT')
      } catch (e) {
        try {
          lite.exec('ROLLBACK')
        } catch {
          /* already rolled back or never begun */
        }
        throw e
      }
    } else if (a.driver === 'postgres') {
      const pg = a.pg!
      await pg.query('BEGIN')
      try {
        for (const sql of statements) {
          await pg.query(sql)
          applied++
        }
        await pg.query('COMMIT')
      } catch (e) {
        await pg.query('ROLLBACK')
        applied = 0
        throw e
      }
    } else {
      for (const sql of statements) {
        await a.my!.query(sql)
        applied++
      }
    }
    return { ok: true, applied }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      applied
    }
  }
}

export async function listDatabases(id: string): Promise<string[]> {
  await ensureLive(id)
  const a = active.get(id)
  if (!a) throw new Error('Not connected')
  if (a.driver === 'sqlite') return [a.config.filePath?.split('/').pop() ?? 'main']
  if (a.driver === 'postgres') {
    const r = await a.pg!.query(
      `select datname from pg_database
        where not datistemplate and has_database_privilege(datname, 'CONNECT')
        order by datname`
    )
    return r.rows.map((x) => String(x.datname))
  }
  const [rows] = await a.my!.query('show databases')
  return (rows as { Database: string }[])
    .map((r) => r.Database)
    .filter((d) => !['information_schema', 'mysql', 'performance_schema', 'sys'].includes(d))
    .sort()
}

export async function useDatabase(cfg: ConnectionConfig, database: string): Promise<ConnectResult> {
  return connect({ ...cfg, database })
}
