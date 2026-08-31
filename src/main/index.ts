import { app, BrowserWindow, dialog, ipcMain, nativeTheme, shell } from 'electron'
import { join } from 'path'
import * as store from './store'
import * as db from './db'
import * as ai from './ai'
import { checkForUpdates, getUpdateState, initUpdater, quitAndInstall } from './updater'
import { canRunInAccessMode, isDestructive, isUnscopedWrite } from './sqlutil'
import { readSshHosts } from './sshconfig'
import { splitStatements } from '../shared/sqlscan'
import type {
  AppSettings,
  ChatMessage,
  ChatSession,
  ConnectionConfig,
  HistoryEntry,
  PendingChange
} from '../shared/types'

const READ_ONLY_ERROR =
  'This connection is read-only. Switch it to Read & write to make changes, or use a database role with the exact permissions this operator needs.'

function backgroundFor(): string {
  return nativeTheme.shouldUseDarkColors ? '#191919' : '#ffffff'
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 880,
    minHeight: 560,
    show: false,
    backgroundColor: backgroundFor(),
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
    titleBarOverlay:
      process.platform === 'darwin'
        ? undefined
        : { color: backgroundFor(), symbolColor: '#8b8b88', height: 44 },
    trafficLightPosition: { x: 18, y: 14 },
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      spellcheck: false
    }
  })

  win.on('ready-to-show', () => win.show())

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })

  if (process.env['ELECTRON_RENDERER_URL']) {
    win.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

function registerHandlers(): void {
  /* ————— connections ————— */
  ipcMain.handle('connections:list', () => store.listConnections())
  ipcMain.handle('connections:save', (_e, cfg: ConnectionConfig) => store.saveConnection(cfg))
  ipcMain.handle('connections:delete', async (_e, id: string) => {
    await db.disconnect(id)
    return store.deleteConnection(id)
  })
  ipcMain.handle('connections:test', (_e, cfg: ConnectionConfig) => db.testConnection(cfg))

  /* ————— live database ————— */
  ipcMain.handle('db:connect', (_e, id: string) => {
    const cfg = store.getFullConfig(id)
    if (!cfg) return { ok: false, error: 'Connection not found' }
    return db.connect(cfg)
  })
  ipcMain.handle('db:disconnect', (_e, id: string) => db.disconnect(id))

  ipcMain.handle('db:query', async (_e, id: string, sql: string) => {
    const settings = store.getSettings()
    // Policy comes from the saved config first so changing Read & write ->
    // Read only takes effect immediately, even if an existing socket is still
    // carrying the connection config it was opened with.
    const cfg = store.getFullConfig(id) ?? db.getConfig(id)
    const access = canRunInAccessMode(cfg?.accessMode, sql)
    if (!access.allowed) return { ok: false, error: access.reason ?? READ_ONLY_ERROR }

    const started = Date.now()
    try {
      const result = await db.runQuery(id, sql, { rowLimit: settings.defaultRowLimit })
      // A read-only connection must also look read-only in the grid. Removing
      // source identity disables inline edit affordances before the user can
      // stage a change; the main-process guards below remain the hard stop.
      if (cfg?.accessMode === 'read-only') {
        result.sets = result.sets.map((set) => ({
          ...set,
          sourceTable: undefined,
          primaryKey: undefined,
          readOnlyReason: 'Connection is read-only'
        }))
      }
      const rowCount = result.sets.reduce((n, s) => n + s.rowCount, 0)
      store.addHistory({
        id: crypto.randomUUID(),
        connectionId: id,
        connectionName: cfg?.name ?? '',
        database: cfg?.database ?? '',
        sql,
        ranAt: started,
        elapsedMs: result.elapsedMs,
        rowCount,
        ok: true
      } satisfies HistoryEntry)
      return { ok: true, result }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      store.addHistory({
        id: crypto.randomUUID(),
        connectionId: id,
        connectionName: cfg?.name ?? '',
        database: cfg?.database ?? '',
        sql,
        ranAt: started,
        elapsedMs: Date.now() - started,
        rowCount: 0,
        ok: false,
        error: message
      } satisfies HistoryEntry)
      return { ok: false, error: message }
    }
  })

  ipcMain.handle('db:cancel', (_e, id: string) => db.cancelQuery(id))
  ipcMain.handle('db:schema', async (_e, id: string) => {
    try {
      return { ok: true, schema: await db.getSchema(id) }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })
  ipcMain.handle('db:tableDetails', async (_e, id: string, schema: string, table: string) => {
    try {
      return { ok: true, details: await db.getTableDetails(id, schema, table) }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })
  ipcMain.handle('db:databases', async (_e, id: string) => {
    try {
      return { ok: true, databases: await db.listDatabases(id) }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })
  ipcMain.handle('db:useDatabase', async (_e, id: string, database: string) => {
    const cfg = store.getFullConfig(id)
    if (!cfg) return { ok: false, error: 'Connection not found' }
    const res = await db.useDatabase(cfg, database)
    if (res.ok) store.saveConnection({ ...cfg, database })
    return res
  })
  ipcMain.handle(
    'db:applyChanges',
    (_e, id: string, table: { schema: string; name: string }, changes: PendingChange[]) => {
      const cfg = store.getFullConfig(id) ?? db.getConfig(id)
      if (cfg?.accessMode === 'read-only') {
        return { ok: false, error: READ_ONLY_ERROR, affected: 0, statements: [] }
      }
      return db.applyChanges(id, table, changes)
    }
  )

  ipcMain.handle('db:alterTable', (_e, id: string, statements: string[]) => {
    const cfg = store.getFullConfig(id) ?? db.getConfig(id)
    if (cfg?.accessMode === 'read-only') return { ok: false, error: READ_ONLY_ERROR, applied: 0 }
    return db.applyAlter(id, statements)
  })

  /* ————— safety ————— */
  ipcMain.handle('safety:check', (_e, id: string, sql: string) => {
    const settings = store.getSettings()
    const cfg = store.getFullConfig(id) ?? db.getConfig(id)
    const statements = splitStatements(sql)
    const unscoped = statements.filter((s) => isUnscopedWrite(s))
    const isProd = cfg?.environment === 'production'
    const needsConfirm =
      settings.confirmDestructive && (unscoped.length > 0 || (isProd && statements.some(isDestructive)))
    return {
      needsConfirm,
      isProduction: isProd,
      unscoped,
      connectionName: cfg?.name ?? ''
    }
  })

  /* ————— history & saved queries ————— */
  ipcMain.handle('history:list', (_e, limit?: number, search?: string) =>
    store.listHistory(limit, search)
  )
  ipcMain.handle('history:clear', () => store.clearHistory())
  ipcMain.handle('saved:list', () => store.listSaved())
  ipcMain.handle('saved:save', (_e, q) => store.saveQuery(q))
  ipcMain.handle('saved:delete', (_e, id: string) => store.deleteSaved(id))

  /* ————— settings ————— */
  ipcMain.handle('settings:get', () => store.getSettings())
  ipcMain.handle('settings:update', (_e, patch: Partial<AppSettings> & { aiKey?: string }) =>
    store.updateSettings(patch)
  )

  // a dropped socket used to be invisible until the next query failed
  db.onConnectionState((id, state, detail) => {
    for (const win of BrowserWindow.getAllWindows()) {
      if (!win.isDestroyed()) win.webContents.send('db:state', { id, state, detail })
    }
  })

  /* ————— chat sessions ————— */
  ipcMain.handle('chats:list', () => store.listChats())
  ipcMain.handle('chats:save', (_e, session: ChatSession) => store.saveChat(session))
  ipcMain.handle('chats:delete', (_e, id: string) => store.deleteChat(id))

  /* ————— AI ————— */
  ipcMain.handle('ai:generate', async (_e, id: string, question: string) => {
    try {
      const schema = await db.getSchema(id)
      const cfg = db.getConfig(id)
      return await ai.generateSql(question, schema, cfg?.driver ?? 'postgres')
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })
  ipcMain.handle('ai:chat', async (e, id: string, transcript: ChatMessage[]) => {
    try {
      const schema = await db.getSchema(id)
      const cfg = db.getConfig(id)
      const send = (text: string): void => {
        if (!e.sender.isDestroyed()) e.sender.send('ai:chat-delta', text)
      }
      return await ai.chat(id, transcript, schema, cfg?.driver ?? 'postgres', send)
    } catch (err) {
      return {
        reply: '',
        queries: [],
        transcript,
        error: err instanceof Error ? err.message : String(err)
      }
    }
  })
  ipcMain.handle(
    'ai:chatResolve',
    async (e, id: string, transcript: ChatMessage[], sql: string, approved: boolean) => {
      try {
        const schema = await db.getSchema(id)
        const cfg = store.getFullConfig(id) ?? db.getConfig(id)
        if (approved && cfg?.accessMode === 'read-only') {
          const blocked = {
            sql,
            autoRun: false,
            status: 'failed' as const,
            error: READ_ONLY_ERROR
          }
          return {
            reply: 'This connection is locked to read-only, so nothing was changed.',
            queries: [blocked],
            transcript: [
              ...transcript,
              {
                role: 'user' as const,
                content:
                  'The connection is read-only, so that statement was not run. Do not retry a write unless the access policy changes.'
              }
            ]
          }
        }
        const send = (text: string): void => {
          if (!e.sender.isDestroyed()) e.sender.send('ai:chat-delta', text)
        }
        return await ai.resolvePending(
          id,
          transcript,
          sql,
          approved,
          schema,
          cfg?.driver ?? 'postgres',
          send
        )
      } catch (err) {
        return {
          reply: '',
          queries: [],
          transcript,
          error: err instanceof Error ? err.message : String(err)
        }
      }
    }
  )
  ipcMain.handle('ai:explain', async (_e, id: string, sql: string) => {
    try {
      const schema = await db.getSchema(id)
      const cfg = db.getConfig(id)
      return await ai.explainSql(sql, schema, cfg?.driver ?? 'postgres')
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })
  ipcMain.handle('ai:fix', async (_e, id: string, sql: string, errorText: string) => {
    try {
      const schema = await db.getSchema(id)
      const cfg = db.getConfig(id)
      return await ai.fixSql(sql, errorText, schema, cfg?.driver ?? 'postgres')
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  })

  /* ————— ssh ————— */
  ipcMain.handle('ssh:hosts', () => {
    try {
      return readSshHosts()
    } catch {
      return []
    }
  })

  /* ————— files & export ————— */
  ipcMain.handle('file:pickSqlite', async () => {
    const res = await dialog.showOpenDialog({
      title: 'Open SQLite database',
      properties: ['openFile'],
      filters: [
        { name: 'SQLite', extensions: ['db', 'sqlite', 'sqlite3', 'db3'] },
        { name: 'All files', extensions: ['*'] }
      ]
    })
    return res.canceled ? null : res.filePaths[0]
  })
  ipcMain.handle('file:pickKey', async () => {
    const res = await dialog.showOpenDialog({
      title: 'Select private key',
      properties: ['openFile', 'showHiddenFiles']
    })
    return res.canceled ? null : res.filePaths[0]
  })
  ipcMain.handle(
    'file:export',
    async (_e, defaultName: string, contents: string, ext: string) => {
      const res = await dialog.showSaveDialog({
        title: 'Export results',
        defaultPath: defaultName,
        filters: [{ name: ext.toUpperCase(), extensions: [ext] }]
      })
      if (res.canceled || !res.filePath) return { ok: false }
      const { writeFileSync } = await import('fs')
      writeFileSync(res.filePath, contents, 'utf-8')
      return { ok: true, path: res.filePath }
    }
  )

  /* ————— updates ————— */
  ipcMain.handle('update:check', () => checkForUpdates())
  ipcMain.handle('update:state', () => getUpdateState())
  ipcMain.handle('update:install', () => quitAndInstall())
}

app.whenReady().then(() => {
  registerHandlers()
  createWindow()
  initUpdater()

  nativeTheme.on('updated', () => {
    for (const win of BrowserWindow.getAllWindows()) {
      win.setBackgroundColor(backgroundFor())
    }
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', async () => {
  await db.disconnectAll()
})
