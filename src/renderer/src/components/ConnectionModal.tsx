import { useEffect, useMemo, useState } from 'react'
import type {
  AccessMode,
  ConnectionConfig,
  ConnectionSummary,
  Driver,
  Environment
} from '../../../shared/types'
import { IconKey, IconMysql, IconPostgres, IconSqlite } from './icons'

interface Props {
  editing: ConnectionSummary | null
  onSave: (cfg: ConnectionConfig) => void
  onDelete: (id: string) => void
  onClose: () => void
}

type SshAuth = 'password' | 'key' | 'agent'
type PostureTone = 'safe' | 'neutral' | 'warn'

const DRIVERS: { id: Driver; label: string; icon: React.JSX.Element; port: number }[] = [
  { id: 'postgres', label: 'PostgreSQL', icon: <IconPostgres />, port: 5432 },
  { id: 'mysql', label: 'MySQL', icon: <IconMysql />, port: 3306 },
  { id: 'sqlite', label: 'SQLite', icon: <IconSqlite />, port: 0 }
]

const ENVIRONMENTS: { id: Environment; label: string; note: string }[] = [
  { id: 'local', label: 'Local', note: '' },
  { id: 'staging', label: 'Staging', note: '' },
  { id: 'production', label: 'Production', note: 'Writes ask for confirmation first.' }
]

const ACCESS_MODES: { id: AccessMode; label: string; note: string }[] = [
  {
    id: 'read-write',
    label: 'Read & write',
    note: 'Normal editor, grid, schema and AI actions. Production write confirmations still apply.'
  },
  {
    id: 'read-only',
    label: 'Read only',
    note: 'Strict local guard: only a single plainly read-only SELECT can execute anywhere in OpenTable.'
  }
]

const defaultPort = (d: Driver): number => DRIVERS.find((x) => x.id === d)?.port ?? 0

/** Parse a postgres:// or mysql:// URL so a pasted connection string just works. */
function parseConnectionUrl(raw: string): Partial<ConnectionConfig> | null {
  const text = raw.trim()
  if (!/^(postgres|postgresql|mysql|mariadb):\/\//i.test(text)) return null
  try {
    const u = new URL(text)
    const driver: Driver = /^mysql|mariadb/i.test(u.protocol) ? 'mysql' : 'postgres'
    const database = decodeURIComponent(u.pathname.replace(/^\//, ''))
    const sslmode = u.searchParams.get('sslmode')
    return {
      driver,
      host: u.hostname || 'localhost',
      port: u.port ? Number(u.port) : defaultPort(driver),
      user: decodeURIComponent(u.username || ''),
      password: u.password ? decodeURIComponent(u.password) : undefined,
      database,
      ssl: sslmode ? sslmode !== 'disable' : false
    }
  } catch {
    return null
  }
}

/**
 * Only classify addresses we can know locally. A private DNS hostname may also
 * be internal, so an unknown hostname is never labelled "public" as a fact.
 */
function isKnownLocalOrPrivateHost(raw: string): boolean {
  const host = raw.trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (!host) return false
  if (host === 'localhost' || host === '::1' || host.endsWith('.localhost')) return true
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return true
  const match172 = /^172\.(\d{1,3})\./.exec(host)
  if (match172) {
    const second = Number(match172[1])
    if (second >= 16 && second <= 31) return true
  }
  if (/^(fc|fd)[0-9a-f]{2}:/i.test(host) || /^fe[89ab][0-9a-f]:/i.test(host)) return true
  return host.endsWith('.internal') || host.endsWith('.local')
}

function connectionPosture(opts: {
  isSqlite: boolean
  host: string
  sshOn: boolean
  sshHost: string
  ssl: boolean
  sslInsecure: boolean
}): { tone: PostureTone; title: string; detail: string } {
  if (opts.isSqlite) {
    return {
      tone: 'safe',
      title: 'Local database file',
      detail: 'No network database port is involved.'
    }
  }
  if (opts.sshOn) {
    return {
      tone: 'safe',
      title: 'SSH tunnel',
      detail: `The database is reached through ${opts.sshHost || 'the bastion host'} instead of exposing its port to this machine.`
    }
  }
  if (opts.ssl && !opts.sslInsecure) {
    return {
      tone: 'safe',
      title: 'Verified TLS',
      detail: 'Traffic to the database is encrypted and the server certificate is verified.'
    }
  }
  if (opts.ssl && opts.sslInsecure) {
    return {
      tone: 'warn',
      title: 'TLS without certificate verification',
      detail: 'Traffic is encrypted, but OpenTable cannot verify which server it reached.'
    }
  }
  if (isKnownLocalOrPrivateHost(opts.host)) {
    return {
      tone: 'neutral',
      title: 'Local / private address',
      detail: 'No TLS is configured. Keep this database on a trusted private network, container network or host-only interface.'
    }
  }
  return {
    tone: 'warn',
    title: 'Direct connection without TLS',
    detail: 'If this hostname is reachable over an untrusted or public network, use SSH, verified TLS, or your provider’s private network instead.'
  }
}

export default function ConnectionModal({
  editing,
  onSave,
  onDelete,
  onClose
}: Props): React.JSX.Element {
  const [name, setName] = useState(editing?.name ?? '')
  const [nameTouched, setNameTouched] = useState(Boolean(editing?.name))
  const [driver, setDriver] = useState<Driver>(editing?.driver ?? 'postgres')
  const [host, setHost] = useState(editing?.host || 'localhost')
  const [port, setPort] = useState<number>(
    editing?.port || defaultPort(editing?.driver ?? 'postgres')
  )
  const [user, setUser] = useState(editing?.user ?? '')
  const [password, setPassword] = useState('')
  const [database, setDatabase] = useState(editing?.database ?? '')
  const [filePath, setFilePath] = useState(editing?.filePath ?? '')
  const [environment, setEnvironment] = useState<Environment>(editing?.environment ?? 'local')
  const [accessMode, setAccessMode] = useState<AccessMode>(editing?.accessMode ?? 'read-write')

  const [ssl, setSsl] = useState(editing?.ssl ?? false)
  const [sslInsecure, setSslInsecure] = useState(editing?.sslInsecure ?? false)

  const [sshOn, setSshOn] = useState(editing?.ssh?.enabled ?? false)
  const [sshAuth, setSshAuth] = useState<SshAuth>(
    editing?.ssh?.authMethod ?? (editing?.ssh?.privateKeyPath ? 'key' : 'agent')
  )
  const [sshHost, setSshHost] = useState(editing?.ssh?.host ?? '')
  const [sshPort, setSshPort] = useState<number>(editing?.ssh?.port ?? 22)
  const [sshUser, setSshUser] = useState(editing?.ssh?.user ?? '')
  const [sshPassword, setSshPassword] = useState('')
  const [sshKeyPath, setSshKeyPath] = useState(editing?.ssh?.privateKeyPath ?? '')
  const [sshPassphrase, setSshPassphrase] = useState('')

  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [pasteNote, setPasteNote] = useState<string | null>(null)
  const [sshHosts, setSshHosts] = useState<
    { alias: string; hostName: string; port: number; user: string; identityFile?: string }[]
  >([])

  useEffect(() => {
    window.opentable.ssh.hosts().then(setSshHosts)
  }, [])

  const isSqlite = driver === 'sqlite'

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  /* ————— derived name: follows what you type until you edit it yourself ————— */
  const suggestedName = useMemo(() => {
    if (isSqlite) return filePath.split('/').pop() ?? ''
    if (!database && !host) return ''
    return database ? `${database}${host && host !== 'localhost' ? ` · ${host}` : ''}` : host
  }, [isSqlite, filePath, database, host])

  const effectiveName = nameTouched && name.trim() ? name.trim() : suggestedName

  /* ————— validation ————— */
  const problems = useMemo(() => {
    const list: string[] = []
    if (isSqlite) {
      if (!filePath.trim()) list.push('Choose a database file')
    } else {
      if (!host.trim()) list.push('Host is required')
      if (!user.trim()) list.push('User is required')
    }
    if (sshOn) {
      if (!sshHost.trim()) list.push('SSH host is required')
      if (!sshUser.trim()) list.push('SSH user is required')
      if (sshAuth === 'key' && !sshKeyPath.trim()) list.push('Choose a private key')
    }
    if (!effectiveName) list.push('Give the connection a name')
    return list
  }, [
    isSqlite,
    filePath,
    host,
    user,
    database,
    driver,
    sshOn,
    sshHost,
    sshUser,
    sshAuth,
    sshKeyPath,
    effectiveName
  ])

  const valid = problems.length === 0

  const buildConfig = (): ConnectionConfig => ({
    id: editing?.id ?? crypto.randomUUID(),
    name: effectiveName,
    driver,
    host: isSqlite ? '' : host.trim(),
    port: isSqlite ? 0 : Number(port) || defaultPort(driver),
    user: isSqlite ? '' : user.trim(),
    password: isSqlite ? undefined : password || undefined,
    database: isSqlite ? '' : database.trim(),
    filePath: isSqlite ? filePath.trim() : undefined,
    environment,
    accessMode,
    ssl: isSqlite ? false : ssl,
    sslInsecure: !isSqlite && ssl ? sslInsecure : false,
    ssh:
      sshOn && !isSqlite
        ? {
            enabled: true,
            host: sshHost.trim(),
            port: Number(sshPort) || 22,
            user: sshUser.trim(),
            authMethod: sshAuth,
            password: sshAuth === 'password' ? sshPassword || undefined : undefined,
            privateKeyPath: sshAuth === 'key' ? sshKeyPath.trim() || undefined : undefined,
            passphrase: sshAuth === 'key' ? sshPassphrase || undefined : undefined
          }
        : undefined
  })

  const switchDriver = (d: Driver): void => {
    setPort((p) => (p === defaultPort(driver) || !p ? defaultPort(d) : p))
    setDriver(d)
    setTestResult(null)
  }

  const applyPaste = async (): Promise<void> => {
    let text = ''
    try {
      text = await navigator.clipboard.readText()
    } catch {
      setPasteNote('Could not read the clipboard')
      return
    }
    const parsed = parseConnectionUrl(text)
    if (!parsed) {
      setPasteNote('No postgres:// or mysql:// URL on the clipboard')
      setTimeout(() => setPasteNote(null), 3000)
      return
    }
    if (parsed.driver) setDriver(parsed.driver)
    if (parsed.host) setHost(parsed.host)
    if (parsed.port) setPort(parsed.port)
    if (parsed.user) setUser(parsed.user)
    if (parsed.password) setPassword(parsed.password)
    if (parsed.database !== undefined) setDatabase(parsed.database)
    if (parsed.ssl) setSsl(true)
    setPasteNote('Filled from the pasted URL')
    setTestResult(null)
    setTimeout(() => setPasteNote(null), 3000)
  }

  const handleTest = async (): Promise<void> => {
    setTesting(true)
    setTestResult(null)
    const res = await window.opentable.connections.test(buildConfig())
    setTesting(false)
    setTestResult(
      res.ok
        ? { ok: true, text: res.serverVersion?.split(' on ')[0] ?? 'Connected' }
        : { ok: false, text: res.error ?? 'Could not connect' }
    )
  }

  const pickFile = async (): Promise<void> => {
    const p = await window.opentable.files.pickSqlite()
    if (p) setFilePath(p)
  }

  /** Turning the tunnel on changes what "host" means, so steer it to the common case. */
  const toggleSsh = (on: boolean): void => {
    setSshOn(on)
    setTestResult(null)
    if (on && (host === 'localhost' || !host.trim())) setHost('127.0.0.1')
  }

  const applySshHost = (alias: string): void => {
    const h = sshHosts.find((x) => x.alias === alias)
    if (!h) return
    setSshHost(h.hostName)
    setSshPort(h.port)
    if (h.user) setSshUser(h.user)
    if (h.identityFile) {
      setSshKeyPath(h.identityFile)
      setSshAuth('key')
    }
    setTestResult(null)
  }

  const pickKey = async (): Promise<void> => {
    const p = await window.opentable.files.pickKey()
    if (p) setSshKeyPath(p)
  }

  const sshSummary = `Through ${sshUser ? sshUser + '@' : ''}${sshHost} · ${
    sshAuth === 'key' ? 'private key' : sshAuth === 'agent' ? 'ssh-agent' : 'password'
  }`

  const posture = useMemo(
    () => connectionPosture({ isSqlite, host, sshOn, sshHost, ssl, sslInsecure }),
    [isSqlite, host, sshOn, sshHost, ssl, sslInsecure]
  )

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal conn-modal">
        <div className="modal-head">
          <h3>{editing ? 'Edit connection' : 'New connection'}</h3>
          {!editing && (
            <button className="paste-url" onClick={applyPaste} title="Paste a connection URL">
              Paste URL
            </button>
          )}
        </div>

        {pasteNote && <div className="paste-note">{pasteNote}</div>}

        <div className="modal-body">
          <div className="driver-picker">
            {DRIVERS.map((d) => (
              <button
                key={d.id}
                className={`driver-card ${driver === d.id ? 'on' : ''}`}
                onClick={() => switchDriver(d.id)}
              >
                <span className="driver-icon">{d.icon}</span>
                <span className="driver-label">{d.label}</span>
              </button>
            ))}
          </div>

          {isSqlite ? (
            <div className="field">
              <label>Database file</label>
              <div className="file-row">
                <input
                  value={filePath}
                  onChange={(e) => setFilePath(e.target.value)}
                  placeholder="/path/to/app.db"
                />
                <button className="btn-mini" onClick={pickFile}>
                  Browse…
                </button>
              </div>
              <span className="field-note">
                SQLite needs no server — OpenTable opens the file directly.
              </span>
            </div>
          ) : (
            <>
              <div className="field-row c31">
                <div className="field">
                  <label>
                    {sshOn ? 'Database host' : 'Host'}
                    {sshOn && <span className="label-opt">as seen from the SSH server</span>}
                  </label>
                  <input
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder={sshOn ? '127.0.0.1' : 'localhost'}
                  />
                </div>
                <div className="field">
                  <label>Port</label>
                  <input
                    type="number"
                    value={port}
                    onChange={(e) => setPort(Number(e.target.value))}
                  />
                </div>
              </div>

              {sshOn && (
                <p className="tunnel-hint">
                  OpenTable signs in to <b>{sshHost || 'the SSH server'}</b>, then reaches the
                  database from there — so these are the database&apos;s own credentials.
                </p>
              )}

              <div className="field-row c2">
                <div className="field">
                  <label>{sshOn ? 'Database user' : 'User'}</label>
                  <input value={user} onChange={(e) => setUser(e.target.value)} />
                </div>
                <div className="field">
                  <label>Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={editing?.hasPassword ? 'Saved — leave blank to keep' : ''}
                  />
                </div>
              </div>

              <div className="field">
                <label>
                  Database<span className="label-opt">optional</span>
                </label>
                <input
                  value={database}
                  onChange={(e) => setDatabase(e.target.value)}
                  placeholder={driver === 'postgres' ? 'postgres' : 'pick one after connecting'}
                />
                <span className="field-note">
                  {driver === 'postgres'
                    ? 'Leave blank to open the postgres maintenance database — you can switch from the sidebar once connected.'
                    : 'Leave blank to connect to the server, then choose from the sidebar.'}
                </span>
              </div>
            </>
          )}

          <div className="field">
            <label>Name</label>
            <input
              value={nameTouched ? name : suggestedName}
              onChange={(e) => {
                setNameTouched(true)
                setName(e.target.value)
              }}
              placeholder="my database"
            />
          </div>

          <div className="field">
            <label>Environment</label>
            <div className="seg env-seg">
              {ENVIRONMENTS.map((e) => (
                <button
                  key={e.id}
                  className={`${environment === e.id ? 'on' : ''} env-${e.id}`}
                  onClick={() => setEnvironment(e.id)}
                >
                  {e.label}
                </button>
              ))}
            </div>
            {environment === 'production' && (
              <span className="field-note warn">
                {ENVIRONMENTS.find((e) => e.id === 'production')?.note}
              </span>
            )}
          </div>

          <div className="field access-policy-field">
            <label>Access policy</label>
            <div className="seg access-seg">
              {ACCESS_MODES.map((mode) => (
                <button
                  key={mode.id}
                  className={accessMode === mode.id ? 'on' : ''}
                  onClick={() => setAccessMode(mode.id)}
                >
                  {mode.label}
                </button>
              ))}
            </div>
            <span className={`field-note ${accessMode === 'read-only' ? 'access-lock-note' : ''}`}>
              {ACCESS_MODES.find((mode) => mode.id === accessMode)?.note}
            </span>
            {accessMode === 'read-only' && (
              <span className="field-note access-auth-note">
                This is defense in depth, not authorization. For staff access, also use a least-privilege
                database role; then the database itself remains the final authority.
              </span>
            )}
          </div>

          {!isSqlite && (
            <>
              <label className="checkline strong">
                <input
                  type="checkbox"
                  checked={sshOn}
                  onChange={(e) => toggleSsh(e.target.checked)}
                />
                Connect through an SSH tunnel
                <span className="checkline-note">
                  {sshOn && sshHost ? sshSummary : 'for a database behind a bastion host'}
                </span>
              </label>

              {sshOn && (
                <>
                  {sshHosts.length > 0 && (
                    <div className="field">
                      <label>
                        From ~/.ssh/config<span className="label-opt">fills the fields below</span>
                      </label>
                      <select value="" onChange={(e) => e.target.value && applySshHost(e.target.value)}>
                        <option value="">Choose a saved host…</option>
                        {sshHosts.map((h) => (
                          <option key={h.alias} value={h.alias}>
                            {h.alias}
                            {h.hostName !== h.alias
                              ? ` — ${h.user ? h.user + '@' : ''}${h.hostName}`
                              : ''}
                          </option>
                        ))}
                      </select>
                    </div>
                  )}

                  <div className="field-row c31">
                    <div className="field">
                      <label>SSH host</label>
                      <input
                        value={sshHost}
                        onChange={(e) => setSshHost(e.target.value)}
                        placeholder="bastion.example.com"
                      />
                    </div>
                    <div className="field">
                      <label>Port</label>
                      <input
                        type="number"
                        value={sshPort}
                        onChange={(e) => setSshPort(Number(e.target.value))}
                      />
                    </div>
                  </div>

                  <div className="field">
                    <label>SSH user</label>
                    <input
                      value={sshUser}
                      onChange={(e) => setSshUser(e.target.value)}
                      placeholder="ubuntu"
                    />
                  </div>

                  <div className="field">
                    <label>Authenticate with</label>
                    <div className="seg">
                      <button
                        className={sshAuth === 'agent' ? 'on' : ''}
                        onClick={() => setSshAuth('agent')}
                      >
                        Agent
                      </button>
                      <button
                        className={sshAuth === 'key' ? 'on' : ''}
                        onClick={() => setSshAuth('key')}
                      >
                        <IconKey /> Key
                      </button>
                      <button
                        className={sshAuth === 'password' ? 'on' : ''}
                        onClick={() => setSshAuth('password')}
                      >
                        Password
                      </button>
                    </div>
                  </div>

                  {sshAuth === 'agent' ? (
                    <span className="field-note">
                      Uses the keys already loaded in your ssh-agent — the same ones <code>ssh</code>{' '}
                      uses. Check them with <code>ssh-add -l</code>.
                    </span>
                  ) : sshAuth === 'password' ? (
                    <div className="field">
                      <label>SSH password</label>
                      <input
                        type="password"
                        value={sshPassword}
                        onChange={(e) => setSshPassword(e.target.value)}
                      />
                    </div>
                  ) : (
                    <>
                      <div className="field">
                        <label>Private key</label>
                        <div className="file-row">
                          <input
                            value={sshKeyPath}
                            onChange={(e) => setSshKeyPath(e.target.value)}
                            placeholder="~/.ssh/id_ed25519"
                          />
                          <button className="btn-mini" onClick={pickKey}>
                            Browse…
                          </button>
                        </div>
                      </div>
                      <div className="field">
                        <label>
                          Key passphrase<span className="label-opt">only if encrypted</span>
                        </label>
                        <input
                          type="password"
                          value={sshPassphrase}
                          onChange={(e) => setSshPassphrase(e.target.value)}
                        />
                      </div>
                    </>
                  )}
                </>
              )}

              <label className="checkline strong">
                <input
                  type="checkbox"
                  checked={ssl}
                  onChange={(e) => {
                    setSsl(e.target.checked)
                    setTestResult(null)
                  }}
                />
                Encrypt the connection with TLS
              </label>

              {ssl && (
                <label className="checkline indented">
                  <input
                    type="checkbox"
                    checked={sslInsecure}
                    onChange={(e) => setSslInsecure(e.target.checked)}
                  />
                  Accept a self-signed certificate
                </label>
              )}
              {ssl && sslInsecure && (
                <span className="field-note warn indented">
                  Certificate verification is skipped — only do this on a network you trust.
                </span>
              )}
            </>
          )}

          <div className={`connection-posture posture-${posture.tone}`}>
            <div className="connection-posture-copy">
              <span className="connection-posture-kicker">Connection safety</span>
              <strong>{posture.title}</strong>
              <span>{posture.detail}</span>
            </div>
            <div className="connection-posture-tags">
              <span>{environment}</span>
              <span className={accessMode === 'read-only' ? 'locked' : ''}>
                {accessMode === 'read-only' ? 'read only' : 'read & write'}
              </span>
            </div>
          </div>
        </div>

        {testResult && (
          <div className={`test-banner ${testResult.ok ? 'ok' : 'err'}`}>
            <span className="test-mark">{testResult.ok ? '✓' : '!'}</span>
            <span className="test-text">{testResult.text}</span>
          </div>
        )}

        <div className="modal-foot">
          {editing && (
            <button className="btn danger" onClick={() => onDelete(editing.id)}>
              Delete
            </button>
          )}
          {!valid && <span className="foot-hint">{problems[0]}</span>}
          <span className="spacer" />
          <button className="btn quiet" onClick={onClose}>
            Cancel
          </button>
          <button className="btn quiet" onClick={handleTest} disabled={testing || !valid}>
            {testing ? 'Testing…' : 'Test'}
          </button>
          <button className="btn primary" onClick={() => onSave(buildConfig())} disabled={!valid}>
            Save
          </button>
        </div>
      </div>
    </div>
  )
}