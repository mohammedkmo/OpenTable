import { createHash, createHmac, timingSafeEqual } from 'crypto'
import { existsSync, readFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'

export type KnownHostStatus = 'trusted' | 'unknown' | 'changed' | 'revoked'

export interface KnownHostCheck {
  status: KnownHostStatus
  /** OpenSSH-style SHA256 fingerprint of the key the server presented. */
  fingerprint: string
  /** Algorithm encoded in the SSH public-key blob, e.g. ssh-ed25519. */
  algorithm: string
  /** Trusted keys for this host using the same algorithm, useful on mismatch. */
  expectedFingerprints: string[]
  /** Files containing entries that participated in the decision. */
  sources: string[]
}

interface KnownHostEntry {
  marker?: string
  hosts: string
  keyType: string
  key: Buffer
  source: string
}

/** OpenSSH uses [host]:port in known_hosts when the port is not 22. */
export function knownHostsTarget(host: string, port: number): string {
  const bare = host.trim().replace(/^\[(.*)\]$/, '$1')
  return port === 22 ? bare : `[${bare}]:${port}`
}

/** Standard user + system trust stores. Missing/unreadable files are ignored. */
export function defaultKnownHostsPaths(): string[] {
  const user = join(homedir(), '.ssh')
  const paths = [join(user, 'known_hosts'), join(user, 'known_hosts2')]
  if (process.platform !== 'win32') {
    paths.push('/etc/ssh/ssh_known_hosts', '/etc/ssh/ssh_known_hosts2')
  }
  return paths
}

function fingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`
}

function keyAlgorithm(key: Buffer): string {
  if (key.length < 4) return 'unknown'
  const length = key.readUInt32BE(0)
  if (length < 1 || 4 + length > key.length) return 'unknown'
  return key.subarray(4, 4 + length).toString('utf-8')
}

function equalBytes(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b)
}

function globMatches(pattern: string, target: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
  try {
    return new RegExp(`^${escaped}$`, 'i').test(target)
  } catch {
    return false
  }
}

/** OpenSSH hashed-host form: |1|base64(salt)|base64(HMAC-SHA1(salt, host)). */
function hashedHostMatches(pattern: string, target: string): boolean {
  const parts = pattern.split('|')
  if (parts.length !== 4 || parts[1] !== '1') return false
  try {
    const salt = Buffer.from(parts[2], 'base64')
    const expected = Buffer.from(parts[3], 'base64')
    if (!salt.length || !expected.length) return false
    const actual = createHmac('sha1', salt).update(target).digest()
    return equalBytes(actual, expected)
  } catch {
    return false
  }
}

function singleHostPatternMatches(pattern: string, target: string): boolean {
  return pattern.startsWith('|1|')
    ? hashedHostMatches(pattern, target)
    : globMatches(pattern, target)
}

/**
 * OpenSSH host lists are comma-separated. A matching negated pattern wins;
 * otherwise at least one positive pattern must match.
 */
function hostListMatches(list: string, target: string): boolean {
  let positive = false
  for (const raw of list.split(',')) {
    if (!raw) continue
    const negated = raw.startsWith('!')
    const pattern = negated ? raw.slice(1) : raw
    if (!singleHostPatternMatches(pattern, target)) continue
    if (negated) return false
    positive = true
  }
  return positive
}

function parseLine(line: string, source: string): KnownHostEntry | null {
  const text = line.trim()
  if (!text || text.startsWith('#')) return null

  const fields = text.split(/\s+/)
  let marker: string | undefined
  let offset = 0
  if (fields[0]?.startsWith('@')) {
    marker = fields[0]
    offset = 1
  }
  if (fields.length < offset + 3) return null

  const hosts = fields[offset]
  const keyType = fields[offset + 1]
  const encoded = fields[offset + 2]
  if (!hosts || !keyType || !encoded) return null

  try {
    const key = Buffer.from(encoded, 'base64')
    if (!key.length) return null
    return { marker, hosts, keyType, key, source }
  } catch {
    return null
  }
}

function readEntries(paths: string[]): KnownHostEntry[] {
  const entries: KnownHostEntry[] = []
  for (const path of paths) {
    if (!existsSync(path)) continue
    let text = ''
    try {
      text = readFileSync(path, 'utf-8')
    } catch {
      continue
    }
    for (const line of text.split(/\r?\n/)) {
      const entry = parseLine(line, path)
      if (entry) entries.push(entry)
    }
  }
  return entries
}

/**
 * Verify the key presented by ssh2 against OpenSSH known_hosts files.
 *
 * A same-algorithm entry with a different key is reported as `changed`. Entries
 * for other algorithms do not cause a false "changed" warning: OpenSSH hosts
 * often legitimately have RSA, ECDSA and Ed25519 keys side-by-side.
 *
 * `@cert-authority` is intentionally not treated as a raw-key match because
 * validating an OpenSSH host certificate requires checking its CA signature,
 * principals and validity period. A directly pinned certificate blob still
 * works like any other ordinary known_hosts entry.
 */
export function verifyKnownHostKey(
  host: string,
  port: number,
  presentedKey: Buffer,
  paths: string[] = defaultKnownHostsPaths()
): KnownHostCheck {
  const target = knownHostsTarget(host, port)
  const presentedAlgorithm = keyAlgorithm(presentedKey)
  const presentedFingerprint = fingerprint(presentedKey)
  const entries = readEntries(paths).filter((entry) => hostListMatches(entry.hosts, target))

  const sources = new Set<string>()
  const expected = new Set<string>()
  let trusted = false
  let changed = false
  let revoked = false

  for (const entry of entries) {
    sources.add(entry.source)

    if (entry.marker === '@cert-authority') continue

    const sameKey = equalBytes(entry.key, presentedKey)
    if (entry.marker === '@revoked') {
      if (sameKey) revoked = true
      continue
    }

    if (sameKey) {
      trusted = true
      continue
    }

    // Only call this a changed key when the host had a pinned key using the
    // same negotiated algorithm. Other algorithms may coexist legitimately.
    if (entry.keyType === presentedAlgorithm) {
      changed = true
      expected.add(fingerprint(entry.key))
    }
  }

  const status: KnownHostStatus = revoked
    ? 'revoked'
    : trusted
      ? 'trusted'
      : changed
        ? 'changed'
        : 'unknown'

  return {
    status,
    fingerprint: presentedFingerprint,
    algorithm: presentedAlgorithm,
    expectedFingerprints: [...expected],
    sources: [...sources]
  }
}

function displayTarget(host: string, port: number): string {
  return port === 22 ? host : `${host}:${port}`
}

/** Actionable message for ssh2's otherwise generic "Host denied" error. */
export function describeHostKeyFailure(
  host: string,
  port: number,
  user: string,
  check: KnownHostCheck
): string {
  const target = displayTarget(host, port)
  const shownAlgorithm = check.algorithm === 'unknown' ? 'SSH' : check.algorithm
  const presented = `${shownAlgorithm} ${check.fingerprint}`

  if (check.status === 'revoked') {
    return `SSH host key for ${target} is marked revoked. Refusing the connection. Presented: ${presented}. Check ${check.sources.join(', ') || 'known_hosts'} and contact the server administrator.`
  }

  if (check.status === 'changed') {
    const known = check.expectedFingerprints.length
      ? ` Known ${shownAlgorithm} fingerprint${check.expectedFingerprints.length === 1 ? '' : 's'}: ${check.expectedFingerprints.join(', ')}.`
      : ''
    return `SSH host key for ${target} has changed. Refusing the connection before credentials are sent. Presented: ${presented}.${known} This can be a rebuilt server or a man-in-the-middle attack; verify the new fingerprint out of band before updating known_hosts.`
  }

  const portArg = port === 22 ? '' : ` -p ${port}`
  return `SSH host key for ${target} is not trusted yet. Refusing the connection before credentials are sent. Presented: ${presented}. Verify this fingerprint with the server administrator, then add the host with OpenSSH (for example: ssh${portArg} ${user ? `${user}@` : ''}${host}) and retry.`
}
