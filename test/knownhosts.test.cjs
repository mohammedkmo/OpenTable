'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const { createHmac } = require('node:crypto')
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join } = require('node:path')

const {
  knownHostsTarget,
  verifyKnownHostKey,
  describeHostKeyFailure
} = require('../.test-dist/main/knownhosts.js')

function sshBlob(type, seed) {
  const name = Buffer.from(type)
  const len = Buffer.alloc(4)
  len.writeUInt32BE(name.length)
  return Buffer.concat([len, name, Buffer.from(seed)])
}

function withKnownHosts(lines, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'opentable-knownhosts-'))
  const file = join(dir, 'known_hosts')
  writeFileSync(file, lines.join('\n') + '\n', 'utf8')
  try {
    return fn(file)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function line(hosts, type, key, marker = '') {
  return `${marker ? marker + ' ' : ''}${hosts} ${type} ${key.toString('base64')}`
}

test('knownHostsTarget follows OpenSSH non-standard port notation', () => {
  assert.equal(knownHostsTarget('db.example.com', 22), 'db.example.com')
  assert.equal(knownHostsTarget('db.example.com', 2222), '[db.example.com]:2222')
  assert.equal(knownHostsTarget('[2001:db8::1]', 2200), '[2001:db8::1]:2200')
})

test('trusts an exact known_hosts key and rejects a changed key of the same algorithm', () => {
  const trusted = sshBlob('ssh-ed25519', 'trusted-key-material')
  const changed = sshBlob('ssh-ed25519', 'different-key-material')

  withKnownHosts([line('bastion.example.com', 'ssh-ed25519', trusted)], (file) => {
    const ok = verifyKnownHostKey('bastion.example.com', 22, trusted, [file])
    assert.equal(ok.status, 'trusted')
    assert.match(ok.fingerprint, /^SHA256:/)

    const bad = verifyKnownHostKey('bastion.example.com', 22, changed, [file])
    assert.equal(bad.status, 'changed')
    assert.equal(bad.expectedFingerprints.length, 1)
    assert.match(
      describeHostKeyFailure('bastion.example.com', 22, 'ubuntu', bad),
      /has changed.*before credentials are sent/i
    )
  })
})

test('does not call a different host-key algorithm a changed key', () => {
  const rsa = sshBlob('ssh-rsa', 'rsa-key')
  const ed25519 = sshBlob('ssh-ed25519', 'ed25519-key')

  withKnownHosts([line('host.example.com', 'ssh-rsa', rsa)], (file) => {
    const result = verifyKnownHostKey('host.example.com', 22, ed25519, [file])
    assert.equal(result.status, 'unknown')
    assert.deepEqual(result.expectedFingerprints, [])
  })
})

test('supports hashed known_hosts entries', () => {
  const key = sshBlob('ssh-ed25519', 'hashed-host-key')
  const target = 'secret.example.com'
  const salt = Buffer.from('0123456789abcdef')
  const digest = createHmac('sha1', salt).update(target).digest()
  const hashed = `|1|${salt.toString('base64')}|${digest.toString('base64')}`

  withKnownHosts([line(hashed, 'ssh-ed25519', key)], (file) => {
    assert.equal(verifyKnownHostKey(target, 22, key, [file]).status, 'trusted')
    assert.equal(verifyKnownHostKey('other.example.com', 22, key, [file]).status, 'unknown')
  })
})

test('matches bracketed host:port entries for non-standard SSH ports', () => {
  const key = sshBlob('ssh-ed25519', 'port-key')

  withKnownHosts([line('[bastion.example.com]:2222', 'ssh-ed25519', key)], (file) => {
    assert.equal(verifyKnownHostKey('bastion.example.com', 2222, key, [file]).status, 'trusted')
    assert.equal(verifyKnownHostKey('bastion.example.com', 22, key, [file]).status, 'unknown')
  })
})

test('honours wildcard host lists and negated patterns', () => {
  const key = sshBlob('ssh-ed25519', 'wildcard-key')

  withKnownHosts([line('*.corp.example.com,!blocked.corp.example.com', 'ssh-ed25519', key)], (file) => {
    assert.equal(verifyKnownHostKey('db.corp.example.com', 22, key, [file]).status, 'trusted')
    assert.equal(verifyKnownHostKey('blocked.corp.example.com', 22, key, [file]).status, 'unknown')
  })
})

test('@revoked overrides an otherwise trusted key', () => {
  const key = sshBlob('ssh-ed25519', 'revoked-key')

  withKnownHosts(
    [
      line('host.example.com', 'ssh-ed25519', key),
      line('host.example.com', 'ssh-ed25519', key, '@revoked')
    ],
    (file) => {
      const result = verifyKnownHostKey('host.example.com', 22, key, [file])
      assert.equal(result.status, 'revoked')
      assert.match(describeHostKeyFailure('host.example.com', 22, 'root', result), /marked revoked/i)
    }
  )
})

test('@cert-authority is not mistaken for a raw host-key pin', () => {
  const ca = sshBlob('ssh-ed25519', 'ca-key')

  withKnownHosts([line('*.example.com', 'ssh-ed25519', ca, '@cert-authority')], (file) => {
    const result = verifyKnownHostKey('db.example.com', 22, ca, [file])
    assert.equal(result.status, 'unknown')
  })
})

test('unknown hosts fail with an actionable fingerprint and ssh command', () => {
  const key = sshBlob('ssh-ed25519', 'new-host-key')

  withKnownHosts([], (file) => {
    const result = verifyKnownHostKey('new.example.com', 2200, key, [file])
    assert.equal(result.status, 'unknown')
    const message = describeHostKeyFailure('new.example.com', 2200, 'deploy', result)
    assert.match(message, /not trusted yet/i)
    assert.match(message, /SHA256:/)
    assert.match(message, /ssh -p 2200 deploy@new\.example\.com/)
  })
})
