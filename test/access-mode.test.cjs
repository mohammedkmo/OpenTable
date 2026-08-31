'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')

const { canRunInAccessMode } = require('../.test-dist/main/sqlutil.js')

test('read-write access preserves existing execution behavior', () => {
  assert.equal(canRunInAccessMode('read-write', 'DELETE FROM users').allowed, true)
  assert.equal(canRunInAccessMode(undefined, 'ALTER TABLE users ADD COLUMN note text').allowed, true)
})

test('read-only access allows plainly read-only SELECTs', () => {
  const allowed = [
    'SELECT id, email FROM users LIMIT 20',
    'WITH x AS (SELECT 1 AS n) SELECT n FROM x',
    "SELECT 'delete from users' AS harmless_text",
    "SELECT replace(name, 'a', 'b') FROM users"
  ]

  for (const sql of allowed) {
    assert.equal(canRunInAccessMode('read-only', sql).allowed, true, sql)
  }
})

test('read-only access blocks writes and stateful read-shaped SQL', () => {
  const blocked = [
    'INSERT INTO users(id) VALUES (1)',
    'UPDATE users SET active = false WHERE id = 1',
    'DELETE FROM users WHERE id = 1',
    'CREATE TABLE users_copy(id int)',
    'ALTER TABLE users ADD COLUMN note text',
    'SELECT * INTO users_backup FROM users',
    'SELECT * FROM users FOR UPDATE',
    "SELECT nextval('orders_id_seq')",
    'SELECT pg_advisory_lock(42)',
    'SELECT 1; DROP TABLE users',
    'WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone'
  ]

  for (const sql of blocked) {
    const verdict = canRunInAccessMode('read-only', sql)
    assert.equal(verdict.allowed, false, sql)
    assert.match(verdict.reason ?? '', /read-only/i)
  }
})
