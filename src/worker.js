let dbReady = false;

const ALLOWED = new Set(['game', 'queue', 'scores', 'levels']);

function splitPath(path) {
  if (typeof path !== 'string' || !path.includes('/')) return null;
  const i = path.lastIndexOf('/');
  const col = path.slice(0, i);
  const id = path.slice(i + 1);
  if (!ALLOWED.has(col) || !id || id.length > 80) return null;
  return { col, id };
}

async function initDb(db) {
  if (dbReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS docs (
      path TEXT PRIMARY KEY,
      col  TEXT NOT NULL,
      id   TEXT NOT NULL,
      data TEXT NOT NULL
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_docs_col ON docs(col)`),
  ]);
  dbReady = true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/db' && request.method === 'POST') {
      try {
        if (!env.DB) {
          return Response.json({ error: 'DB binding missing' }, { status: 500 });
        }

        const body = await request.json();
        const { op, path, data, holder, ttlMs } = body || {};

        if (op === 'ping') {
          await initDb(env.DB);
          return Response.json({ ok: true });
        }

        await initDb(env.DB);

        if (op === 'list') {
          if (!ALLOWED.has(path)) {
            return Response.json({ error: 'bad collection' }, { status: 400 });
          }
          const { results } = await env.DB
            .prepare('SELECT id, data FROM docs WHERE col = ?')
            .bind(path)
            .all();
          const rows = results.map((r) => ({ id: r.id, data: JSON.parse(r.data) }));
          return Response.json({ rows });
        }

        const parts = splitPath(path);
        if (!parts) {
          return Response.json({ error: 'bad path' }, { status: 400 });
        }

        if (op === 'get') {
          const row = await env.DB
            .prepare('SELECT data FROM docs WHERE path = ?')
            .bind(path)
            .first();
          return Response.json({ data: row ? JSON.parse(row.data) : null });
        }

        if (op === 'set') {
          const raw = JSON.stringify(data ?? null);
          if (raw.length > 200000) {
            return Response.json({ error: 'payload too large' }, { status: 413 });
          }
          await env.DB
            .prepare(
              'INSERT INTO docs (path, col, id, data) VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data'
            )
            .bind(path, parts.col, parts.id, raw)
            .run();
          return Response.json({ ok: true });
        }

        if (op === 'update') {
          const row = await env.DB
            .prepare('SELECT data FROM docs WHERE path = ?')
            .bind(path)
            .first();
          const cur = row ? JSON.parse(row.data) : {};
          const raw = JSON.stringify({ ...cur, ...(data || {}) });
          if (raw.length > 200000) {
            return Response.json({ error: 'payload too large' }, { status: 413 });
          }
          await env.DB
            .prepare(
              'INSERT INTO docs (path, col, id, data) VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data'
            )
            .bind(path, parts.col, parts.id, raw)
            .run();
          return Response.json({ ok: true });
        }

        if (op === 'delete') {
          await env.DB.prepare('DELETE FROM docs WHERE path = ?').bind(path).run();
          return Response.json({ ok: true });
        }

        if (op === 'acquire') {
          const now = Date.now();
          const lock = JSON.stringify({
            holder: String(holder || ''),
            until: now + Math.min(Math.max(Number(ttlMs) || 4000, 1000), 15000),
          });
          const res = await env.DB
            .prepare(
              `INSERT INTO docs (path, col, id, data) VALUES (?, ?, ?, ?)
               ON CONFLICT(path) DO UPDATE SET data = excluded.data
               WHERE json_extract(docs.data, '$.holder') = ?
                  OR json_extract(docs.data, '$.until') <= ?`
            )
            .bind(path, parts.col, parts.id, lock, String(holder || ''), now)
            .run();
          return Response.json({ acquired: (res.meta?.changes || 0) > 0 });
        }

        return Response.json({ error: 'unknown op' }, { status: 400 });
      } catch (err) {
        return Response.json({ error: err.message || 'server error' }, { status: 500 });
      }
    }

    return env.ASSETS.fetch(request);
  },
};
