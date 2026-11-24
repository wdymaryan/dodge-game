/* ============================================================================
 * Dodge — Cloudflare Worker + D1 Backend (v2.2 — Production Hardened)
 * Backward-compatible with D1 schema: docs(path PRIMARY KEY, col, id, data)
 * Allowed collections: game, queue, scores, levels
 *
 * Security & Features:
 *  - HMAC-SHA256 bound UID session tokens (prevents UID spoofing / hijacking)
 *  - Signed turn session nonces (turnToken) required for level clears & turn end
 *  - Batched `sync` endpoint returning all lobby/game state in a single round-trip
 *  - Server-side anti-cheat: min theoretical clear time, monotonic level checks,
 *    frame/input telemetry validation, schema/range clamping, nickname sanitization
 *  - Tuned per-IP & per-UID sliding-window rate limiting + 64KB payload limit
 *  - 10-second reconnect grace period (2.5s heartbeats, pagehide disconnect mark,
 *    auto-resume for same authenticated UID, auto-finalize after 10s)
 *  - Dual game modes: Time Attack (per-level verified times) & Infinity Relay
 *    (shared global progression under game/relay)
 *  - Server-verified Pro Clutches, Ultra-Hard Achievements & Equippable Rewards
 * ============================================================================ */

const ALLOWED_COLS = new Set(['game', 'queue', 'scores', 'levels']);
const INTERNAL_DOCS = new Set(['game/session', 'game/lock']);
const DURS = [60000, 180000, 300000];
const DAILY_MAX_MS = 1800000;
const VALID_MODES = new Set(['time_attack', 'relay']);
const VALID_TILES = new Set(['.', '#', 'i', 'b', 'c', '^', 'e', 'q', 'x', 'o', 'u', 'f', 'r', 'd', 'w', 'v', 'm', 'n', 'S', 'G', 'K', 'p', 'y', 'z', '*', 'a', 's', 't']);
const VALID_THEMES = new Set(['dusk', 'concrete', 'harbor', 'neon', 'mint', 'aurora', 'candy', 'void', 'ember', 'toxic', 'frost', 'sand', 'lava', 'sky']);
const VALID_CLUTCHES = new Set(['saviour', 'phantom', 'razor', 'wallsave', 'buzzer', 'skim', 'orbchain', 'chase']);

/* ---------- Pro Achievements & Unlockable Rewards Registry ---------- */
const ACH_REWARDS = {
  saviour:     { slot: 'aura',  id: 'halo',      title: 'SAVIOUR' },
  phantom:     { slot: 'trail', id: 'ghost',     title: 'PHANTOM' },
  razor:       { slot: 'skin',  id: 'obsidian',  title: 'FRAME-1' },
  buzzer:      { slot: 'trail', id: 'ember',     title: 'CLUTCH' },
  untouchable: { slot: 'skin',  id: 'plasma',    title: 'UNTOUCHABLE' },
  godspeed:    { slot: 'trail', id: 'lightning', title: 'GODSPEED' },
  iron_will:   { slot: 'skin',  id: 'crimson',   title: 'IRON' },
  night_owl:   { slot: 'aura',  id: 'sonar',     title: 'BLIND' },
  death_defier:{ slot: 'aura',  id: 'flame',     title: 'DEFIER' },
  sky_dancer:  { slot: 'trail', id: 'prism',     title: 'SKY' },
  centurion:   { slot: 'skin',  id: 'astral',    title: 'LV.100' },
  clutch_god:  { slot: 'aura',  id: 'apex',      title: 'APEX' },
  striker:     { slot: 'skin',  id: 'cobalt',    title: 'LV.10' },
  vanguard:    { slot: 'trail', id: 'volt',      title: 'LV.25' },
  overdrive:   { slot: 'aura',  id: 'pulse',     title: 'LV.50' },
  immortal:    { slot: 'skin',  id: 'titanium',  title: 'LV.200' }
};

const hasOwn = (o, k) => !!o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

function ownedRewardsFor(achievements = {}, claimed = {}) {
  const skins = new Set(['default']);
  const trails = new Set(['default']);
  const auras = new Set(['none']);
  const titles = new Set(['']);
  for (const [achId, meta] of Object.entries(ACH_REWARDS)) {
    if (hasOwn(achievements, achId) && achievements[achId] && hasOwn(claimed, achId) && claimed[achId]) {
      if (meta.slot === 'skin') skins.add(meta.id);
      else if (meta.slot === 'trail') trails.add(meta.id);
      else if (meta.slot === 'aura') auras.add(meta.id);
      if (meta.title) titles.add(meta.title);
    }
  }
  return { skins, trails, auras, titles };
}

const MAX_BODY_BYTES = 65536;
const RECONNECT_GRACE_MS = 10000;
const HEARTBEAT_SILENT_DROP_MS = 7500;
const QUEUE_STALE_MS = 25000;
const QUEUE_PURGE_MS = 90000;
const TURN_COUNTDOWN_MS = 4500;
const TURN_END_BUFFER_MS = 1500;

// Rate limiter buckets (per isolate) — tuned for batched sync + rapid level clears
const IP_RATE_LIMIT = 180;
const UID_RATE_LIMIT = 60;
const RATE_WINDOW_MS = 10000;
const ipBuckets = new Map();
const uidBuckets = new Map();
let lastRlPrune = 0;

function checkRateLimit(map, key, limit, windowMs, now) {
  if (now - lastRlPrune > 30000) {
    lastRlPrune = now;
    for (const [k, b] of ipBuckets) if (now - b.start > 60000) ipBuckets.delete(k);
    for (const [k, b] of uidBuckets) if (now - b.start > 60000) uidBuckets.delete(k);
  }
  let b = map.get(key);
  if (!b || now - b.start >= windowMs) {
    b = { start: now, count: 0 };
    map.set(key, b);
  }
  b.count++;
  return b.count <= limit;
}

/* ---------- Crypto / HMAC helpers (Web Crypto API) ---------- */
const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return toHex(a);
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSign(secret, msg) {
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return toHex(sig);
}

let warnedSecret = false;
function getSecret(env) {
  if (env && env.HMAC_SECRET) return env.HMAC_SECRET;
  if (!warnedSecret) {
    warnedSecret = true;
    console.warn('HMAC_SECRET is not set: using the built-in fallback. Set it with `wrangler secret put HMAC_SECRET` before going live.');
  }
  return 'dodge-v2-hmac-secret-4f0c2990-6730-4768-a3f3';
}

async function makeUidToken(secret, uid) {
  const sig = await hmacSign(secret, 'uid:' + uid);
  return sig.slice(0, 32);
}

async function verifyUidToken(secret, uid, token) {
  if (!isValidUid(uid) || typeof token !== 'string' || token.length !== 32) return false;
  const expected = await makeUidToken(secret, uid);
  return timingSafeEqual(expected, token);
}

async function makeTurnToken(secret, uid, rev, mode, nonce) {
  const sig = await hmacSign(secret, `turn:${uid}:${rev}:${mode}:${nonce}`);
  return `${nonce}.${sig.slice(0, 32)}`;
}

async function verifyTurnToken(secret, uid, rev, mode, token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [nonce, sig] = parts;
  if (!nonce || nonce.length < 8 || !sig || sig.length !== 32) return false;
  const expected = await makeTurnToken(secret, uid, rev, mode, nonce);
  return timingSafeEqual(expected, token);
}

/* ---------- Sanitizers & Validators ---------- */
function isValidUid(uid) {
  return typeof uid === 'string' && /^[a-zA-Z0-9_-]{4,48}$/.test(uid);
}

function sanitizeNick(raw) {
  if (typeof raw !== 'string') return '';
  return raw.replace(/[^\w \-.]/g, '').replace(/\s+/g, ' ').trim().slice(0, 14);
}

function sanitizeMode(raw) {
  return VALID_MODES.has(raw) ? raw : 'time_attack';
}

function clampInt(v, min, max, fallback = min) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function clampNum(v, min, max, fallback = min) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function dayKey(now = Date.now()) {
  return new Date(now).toISOString().slice(0, 10);
}

function hashStr(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

function lenFor(waiting) {
  return waiting >= 3 ? 60000 : waiting >= 1 ? 180000 : 300000;
}

function parsePath(path) {
  if (typeof path !== 'string') return null;
  const parts = path.split('/').filter(Boolean);
  if (parts.length === 1 && ALLOWED_COLS.has(parts[0])) return { col: parts[0], id: null, path: parts[0] };
  if (parts.length === 2 && ALLOWED_COLS.has(parts[0]) && /^[a-zA-Z0-9_-]{1,64}$/.test(parts[1])) {
    return { col: parts[0], id: parts[1], path: `${parts[0]}/${parts[1]}` };
  }
  return null;
}

/* ---------- D1 Storage Helpers ---------- */
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(
    'CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, col TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL)'
  ).run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_docs_col ON docs(col)').run();
  schemaReady = true;
}

async function dbGet(db, path) {
  const row = await db.prepare('SELECT data FROM docs WHERE path = ?').bind(path).first();
  if (!row) return null;
  try { return JSON.parse(row.data); } catch { return null; }
}

async function dbSet(db, path, data) {
  const p = parsePath(path);
  if (!p || !p.id) throw new Error('invalid_path');
  const json = JSON.stringify(data);
  await db.prepare(
    'INSERT INTO docs(path, col, id, data) VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data'
  ).bind(p.path, p.col, p.id, json).run();
}

async function dbDelete(db, path) {
  await db.prepare('DELETE FROM docs WHERE path = ?').bind(path).run();
}

async function dbList(db, col) {
  const res = await db.prepare('SELECT id, data FROM docs WHERE col = ?').bind(col).all();
  const rows = [];
  for (const r of (res.results || [])) {
    try { rows.push({ id: r.id, data: JSON.parse(r.data) }); } catch { /* skip corrupt */ }
  }
  return rows;
}

/* Atomic lock: a single conditional upsert, so two simultaneous `advance` calls can't both win. */
async function acquireLock(db, holder, now, ttlMs) {
  const data = JSON.stringify({ holder, expiresAt: now + ttlMs });
  const res = await db.prepare(
    "INSERT INTO docs(path, col, id, data) VALUES ('game/lock', 'game', 'lock', ?) " +
    "ON CONFLICT(path) DO UPDATE SET data = excluded.data " +
    "WHERE COALESCE(json_extract(docs.data, '$.expiresAt'), 0) <= ? OR json_extract(docs.data, '$.holder') = ?"
  ).bind(data, now, holder).run();
  const changes = res && res.meta && typeof res.meta.changes === 'number' ? res.meta.changes : 1;
  return changes > 0;
}

/* ---------- Game State & Grace Period Helpers ---------- */
function getGraceInfo(st, now) {
  if (!st || !st.runner || st.done) return { disconnected: false, graceEndsAt: 0, graceExpired: false };
  if (st.disconnectedAt && Number.isFinite(st.disconnectedAt)) {
    const graceEndsAt = st.disconnectedAt + RECONNECT_GRACE_MS;
    return { disconnected: true, graceEndsAt, graceExpired: now >= graceEndsAt };
  }
  const refTime = st.lastHbAt || st.issuedAt || 0;
  if (refTime > 0 && now - refTime > HEARTBEAT_SILENT_DROP_MS) {
    const inferredDisconnect = refTime + HEARTBEAT_SILENT_DROP_MS;
    const graceEndsAt = inferredDisconnect + RECONNECT_GRACE_MS;
    return { disconnected: true, graceEndsAt, graceExpired: now >= graceEndsAt, inferredDisconnect };
  }
  return { disconnected: false, graceEndsAt: 0, graceExpired: false };
}

function isTurnOver(st, now) {
  if (!st || !st.runner || st.done) return true;
  if (st.endsAt && now > st.endsAt + TURN_END_BUFFER_MS) return true;
  const g = getGraceInfo(st, now);
  if (g.graceExpired) return true;
  return false;
}

function sanitizePublicState(st, now) {
  if (!st) return null;
  const g = getGraceInfo(st, now);
  const out = Object.assign({}, st);
  delete out.turnToken;
  delete out.turnNonce;
  if (g.disconnected && !out.disconnectedAt && g.inferredDisconnect) {
    out.disconnectedAt = g.inferredDisconnect;
  }
  if (g.disconnected) {
    out.graceEndsAt = g.graceEndsAt;
    out.graceLeftMs = Math.max(0, g.graceEndsAt - now);
  } else {
    out.graceEndsAt = 0;
    out.graceLeftMs = 0;
  }
  out.serverNow = now;
  return out;
}

/* ---------- Anti-Cheat: Physics-Based Clear Speed & Telemetry Validation ---------- */
function minTheoreticalClearMs(levelNum, levelW, cfg = {}) {
  const effectiveW = Math.max(24, clampInt(levelW, 16, 260, 48));
  const minDistanceTiles = Math.max(14, effectiveW - 10);
  const speedMult = cfg && cfg.speed ? clampNum(cfg.speed, 0.8, 1.35, 1) : 1;
  const maxAvgTilesPerSec = 15.8 * speedMult;
  const rawMs = Math.floor((minDistanceTiles / maxAvgTilesPerSec) * 1000);
  const floorMs = (levelNum % 5 === 0) ? 900 : 1800;
  return Math.max(floorMs, rawMs);
}

function validateCommunityLevelsDoc(uid, nick, items) {
  if (!items || typeof items !== 'object' || Array.isArray(items)) return { error: 'invalid_items' };
  const keys = Object.keys(items);
  if (keys.length > 20) return { error: 'level_limit_exceeded' };
  const clean = {};
  for (const id of keys) {
    if (!/^[a-zA-Z0-9_-]{2,40}$/.test(id)) return { error: 'invalid_level_id' };
    const it = items[id];
    if (!it || typeof it !== 'object') return { error: 'invalid_level' };
    const w = clampInt(it.w, 16, 120, 0);
    const h = clampInt(it.h, 12, 30, 0);
    if (!Array.isArray(it.rows) || it.rows.length !== h) return { error: 'invalid_rows' };
    let starts = 0, goals = 0;
    const cleanRows = [];
    for (const r of it.rows) {
      if (typeof r !== 'string' || r.length !== w) return { error: 'invalid_row_width' };
      for (let i = 0; i < r.length; i++) {
        const ch = r[i];
        if (!VALID_TILES.has(ch)) return { error: 'invalid_tile' };
        if (ch === 'S') starts++;
        if (ch === 'G') goals++;
      }
      cleanRows.push(r);
    }
    if (starts !== 1 || goals !== 1) return { error: 'invalid_start_goal' };
    const cfg = it.cfg && typeof it.cfg === 'object' ? it.cfg : {};
    const cleanCfg = {
      theme: VALID_THEMES.has(cfg.theme) ? cfg.theme : 'dusk',
      grav: clampNum(cfg.grav, 0.5, 2.0, 1),
      speed: clampNum(cfg.speed, 0.6, 1.5, 1),
      jumps: clampInt(cfg.jumps, 1, 3, 1),
      wall: cfg.wall !== false,
      ms: clampNum(cfg.ms, 1.0, 6.0, 2.6),
      dash: cfg.dash !== false,
      bs: clampNum(cfg.bs, 3.0, 12.0, 6.5),
      bp: clampNum(cfg.bp, 1.0, 5.0, 2.4),
      dark: !!cfg.dark,
      slick: !!cfg.slick
    };
    const name = String(it.name || 'Untitled').replace(/[^\w \-.'!?]/g, '').trim().slice(0, 24) || 'Untitled';
    clean[id] = {
      name, w, h, rows: cleanRows, cfg: cleanCfg,
      at: clampInt(it.at, 0, Date.now() + 60000, Date.now()),
      verified: !!it.verified
    };
  }
  return { data: { uid, nick: sanitizeNick(nick) || 'Player', items: clean } };
}

/* ---------- Relay & Score Persistence ---------- */
function isRelayMilestone(lv) {
  if (lv <= 1) return false;
  if (lv <= 50) return lv % 5 === 0;
  if (lv <= 100) return lv % 10 === 0;
  return lv % 25 === 0;
}

async function getOrInitRelay(db, now) {
  const cur = await dbGet(db, 'game/relay');
  if (cur && typeof cur.relayLevel === 'number') return cur;
  const init = {
    relayLevel: 1,
    totalClears: 0,
    milestones: {},
    lastRunner: null,
    seed: hashStr('lr-relay-v2'),
    updatedAt: now
  };
  await dbSet(db, 'game/relay', init);
  return init;
}

function defaultScoreDoc(uid, nick) {
  return {
    uid,
    nick: sanitizeNick(nick) || 'Player',
    runs: 0,
    level: 1,
    levelAt: 0,
    totalCleared: 0,
    relayCleared: 0,
    relayMilestones: [],
    levelBestMs: {},
    achievements: {},
    claimed: {},
    clutches: { total: 0, byType: {} },
    equipped: { skin: 'default', trail: 'default', aura: 'none', title: '' },
    best: {},
    today: {},
    recent: []
  };
}

function sanitizeClutchesList(raw, cfg) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const c of raw.slice(0, 24)) {
    const t = String(c || '');
    if (!VALID_CLUTCHES.has(t)) continue;
    if (t === 'chase' && !(cfg && Number(cfg.chase) > 0)) continue;
    out.push(t);
  }
  return out;
}

function evaluateLevelAchievements(sc, sess, st, claimedLevel, deaths, levelClutches, cfg, mods, now) {
  if (!sc.achievements || typeof sc.achievements !== 'object') sc.achievements = {};
  if (!sc.clutches || typeof sc.clutches !== 'object') sc.clutches = { total: 0, byType: {} };
  if (!sc.clutches.byType || typeof sc.clutches.byType !== 'object') sc.clutches.byType = {};

  for (const c of levelClutches) {
    sc.clutches.total = (Number(sc.clutches.total) || 0) + 1;
    sc.clutches.byType[c] = (Number(sc.clutches.byType[c]) || 0) + 1;
  }

  const flawless = deaths === 0;
  sess.flawlessStreak = flawless ? ((Number(sess.flawlessStreak) || 0) + 1) : 0;
  sess.turnDeaths = (Number(sess.turnDeaths) || 0) + deaths;
  if (!Array.isArray(sess.turnClutchTypes)) sess.turnClutchTypes = [];
  for (const c of levelClutches) {
    if (!sess.turnClutchTypes.includes(c)) sess.turnClutchTypes.push(c);
  }
  sess.razorTurnCount = (Number(sess.razorTurnCount) || 0) + (flawless ? levelClutches.filter(c => c === 'razor').length : 0);

  const newlyUnlocked = [];
  // `once` = progress milestones: unlock a single time, never count up
  const unlock = (id, once = false) => {
    if (!hasOwn(ACH_REWARDS, id)) return;
    if (!sc.achievements[id]) {
      sc.achievements[id] = { at: now, count: 1 };
      newlyUnlocked.push(id);
    } else if (!once) {
      sc.achievements[id].count = (Number(sc.achievements[id].count) || 1) + 1;
    }
  };

  if (flawless && levelClutches.includes('saviour')) unlock('saviour');
  if (flawless && levelClutches.filter(c => c === 'phantom').length >= 5) unlock('phantom');
  if (sess.razorTurnCount >= 3 && !sess.razorAwarded) { sess.razorAwarded = true; unlock('razor'); }

  const timeLeftMs = st.endsAt - now;
  if (flawless && timeLeftMs > 0 && timeLeftMs <= 2200) {
    if (!levelClutches.includes('buzzer')) {
      sc.clutches.total = (Number(sc.clutches.total) || 0) + 1;
      sc.clutches.byType.buzzer = (Number(sc.clutches.byType.buzzer) || 0) + 1;
    }
    unlock('buzzer');
  }

  if (sess.flawlessStreak > 0 && sess.flawlessStreak % 10 === 0) unlock('untouchable');
  if (!sess.godspeedAwarded && ((st.dur === 180000 && st.cleared >= 15) || (st.dur === 60000 && st.cleared >= 7))) { sess.godspeedAwarded = true; unlock('godspeed'); }

  const modList = Array.isArray(mods) ? mods : [];
  if (flawless && claimedLevel >= 25 && (modList.includes('iron') || modList.length >= 2)) unlock('iron_will');
  if (flawless && claimedLevel >= 12 && cfg && cfg.dark && levelClutches.length >= 1) unlock('night_owl');
  if (flawless && cfg && Number(cfg.chase) > 0 && levelClutches.includes('chase')) unlock('death_defier');
  if (flawless && levelClutches.includes('orbchain')) unlock('sky_dancer');
  // Level milestones only count Time Attack progress: in Relay st.n starts at the shared global level,
  // so one clear at relay level 199 would otherwise hand out LV.200 instantly.
  if (st.mode === 'time_attack') {
    if (st.n >= 10) unlock('striker', true);
    if (st.n >= 25) unlock('vanguard', true);
    if (st.n >= 50) unlock('overdrive', true);
    if (claimedLevel >= 99 && st.n >= 100) unlock('centurion', true);
    if (st.n >= 200) unlock('immortal', true);
  }
  if (sess.turnDeaths === 0 && sess.turnClutchTypes.length >= 5 && !sess.clutchGodAwarded) { sess.clutchGodAwarded = true; unlock('clutch_god'); }

  return newlyUnlocked;
}

async function recordRunToScore(db, uid, nick, dur, cleared, reached, mode, now) {
  const cur = (await dbGet(db, 'scores/' + uid)) || defaultScoreDoc(uid, nick);
  const d = dayKey(now);
  const k = String(DURS.includes(dur) ? dur : 180000);
  const best = Object.assign({}, cur.best);
  const today = cur.today && cur.today.d === d ? Object.assign({}, cur.today) : { d };
  const cleanMode = sanitizeMode(mode);

  if (cleanMode === 'time_attack' && cleared > 0) {
    if (!best[k] || cleared > best[k].n) best[k] = { n: cleared, at: now };
    if (!today[k] || cleared > today[k].n) today[k] = { n: cleared, at: now };
  }

  // Only Time Attack updates personal highest Time Attack level; Infinity Relay tracks relayCleared & milestones separately
  const prevLevel = Math.max(1, Number(cur.level) || 1);
  const level = cleanMode === 'time_attack'
    ? Math.max(prevLevel, Math.max(1, Number(reached) || 1))
    : prevLevel;
  const levelAt = level > prevLevel ? now : (cur.levelAt || (level > 1 ? now : 0));
  const totalCleared = (Number(cur.totalCleared) || 0) + Math.max(0, cleared);
  const recent = [{ dur: Number(k), n: cleared, level: Math.max(1, Number(reached) || 1), mode: cleanMode, at: now }]
    .concat(Array.isArray(cur.recent) ? cur.recent : [])
    .slice(0, 16);

  const rec = Object.assign(defaultScoreDoc(uid, nick), cur, {
    uid,
    nick: sanitizeNick(nick) || cur.nick || 'Player',
    runs: (Number(cur.runs) || 0) + 1,
    level,
    levelAt,
    totalCleared,
    best,
    today,
    recent
  });
  await dbSet(db, 'scores/' + uid, rec);
  return rec;
}

async function finalizeTurnInternal(db, st, now, manual = false) {
  if (!st || !st.runner || st.done) return st;
  const uid = st.runner;
  const nick = st.nick || 'Player';
  const cleared = Math.max(0, Number(st.cleared) || 0);
  const dur = DURS.includes(st.dur) ? st.dur : 180000;
  const reached = Math.max(1, Number(st.n) || 1);
  const mode = sanitizeMode(st.mode);

  const doneState = {
    runner: null,
    done: true,
    dur,
    mode,
    cleared,
    n: reached,
    hb: (Number(st.hb) || 0) + 1,
    rev: (Number(st.rev) || 0) + 1,
    last: { nick, cleared, dur, level: reached, mode, uid, manual: !!manual, title: st.title || '' },
    issuedAt: now,
    lastHbAt: now,
    disconnectedAt: null
  };
  await dbSet(db, 'game/state', doneState);
  await dbDelete(db, 'game/session');

  const rec = await recordRunToScore(db, uid, nick, dur, cleared, reached, mode, now);
  return { state: doneState, score: rec };
}

/* ---------- Main API Handler ---------- */
function jsonRes(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }, extraHeaders)
  });
}

async function handleApi(request, env) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  if (request.method !== 'POST') return jsonRes({ error: 'method_not_allowed' }, 405);

  const now = Date.now();
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'local';
  if (!checkRateLimit(ipBuckets, ip, IP_RATE_LIMIT, RATE_WINDOW_MS, now)) {
    return jsonRes({ error: 'rate_limited' }, 429, { 'retry-after': '5' });
  }

  const rawText = await request.text();
  if (rawText.length > MAX_BODY_BYTES) return jsonRes({ error: 'payload_too_large' }, 413);
  let body;
  try { body = JSON.parse(rawText); } catch { return jsonRes({ error: 'invalid_json' }, 400); }
  if (!body || typeof body !== 'object') return jsonRes({ error: 'invalid_body' }, 400);

  const db = env.DB;
  if (!db) return jsonRes({ error: 'db_not_configured' }, 500);
  await ensureSchema(db);

  const secret = getSecret(env);
  const op = String(body.op || '');

  if (op === 'ping') return jsonRes({ ok: true, serverNow: now });

  if (op === 'auth') {
    const reqUid = body.uid;
    const reqToken = body.token;
    if (isValidUid(reqUid) && await verifyUidToken(secret, reqUid, reqToken)) {
      return jsonRes({ ok: true, uid: reqUid, token: reqToken, serverNow: now });
    }
    let uid = null;
    if (isValidUid(reqUid) && !reqToken) {
      const [s, l, q] = await Promise.all([
        dbGet(db, 'scores/' + reqUid),
        dbGet(db, 'levels/' + reqUid),
        dbGet(db, 'queue/' + reqUid)
      ]);
      if (!s && !l && !q) uid = reqUid;
    }
    if (!uid) uid = 'u_' + randomHex(10);
    const token = await makeUidToken(secret, uid);
    return jsonRes({ ok: true, uid, token, serverNow: now });
  }

  /* ---- Batched Sync Endpoint (replaces 6 parallel poll requests with 1) ---- */
  if (op === 'sync') {
    const inc = Array.isArray(body.include) ? new Set(body.include) : null;
    const want = k => !inc || inc.has(k);
    const [rawState, relay, rawLevelTimes, qRows, sRows, lRows] = await Promise.all([
      want('state') ? dbGet(db, 'game/state') : Promise.resolve(undefined),
      want('relay') ? getOrInitRelay(db, now) : Promise.resolve(undefined),
      want('levelTimes') ? dbGet(db, 'game/level_times') : Promise.resolve(undefined),
      want('queue') ? dbList(db, 'queue') : Promise.resolve(undefined),
      want('scores') ? dbList(db, 'scores') : Promise.resolve(undefined),
      want('levels') ? dbList(db, 'levels') : Promise.resolve(undefined)
    ]);
    const out = { ok: true, serverNow: now };
    if (want('state')) out.state = sanitizePublicState(rawState, now);
    if (want('relay')) out.relay = relay;
    if (want('levelTimes')) out.levelTimes = rawLevelTimes || { levels: {}, updatedAt: now };
    if (want('queue')) out.queue = qRows.map(r => r.data).filter(Boolean);
    if (want('scores')) out.scores = sRows.map(r => r.data).filter(Boolean);
    if (want('levels')) out.levels = lRows.map(r => r.data).filter(Boolean);
    return jsonRes(out);
  }

  if (op === 'get') {
    const p = parsePath(body.path);
    if (!p || !p.id) return jsonRes({ error: 'invalid_path' }, 400);
    if (INTERNAL_DOCS.has(p.path)) return jsonRes({ error: 'forbidden' }, 403);
    let data = await dbGet(db, p.path);
    if (p.path === 'game/state') data = sanitizePublicState(data, now);
    else if (p.path === 'game/relay' && !data) data = await getOrInitRelay(db, now);
    else if (p.path === 'game/level_times' && !data) data = { levels: {}, updatedAt: now };
    return jsonRes({ data, serverNow: now });
  }

  if (op === 'list') {
    const p = parsePath(body.path);
    if (!p || p.id) return jsonRes({ error: 'invalid_collection' }, 400);
    let rows = await dbList(db, p.col);
    if (p.col === 'game') {
      rows = rows.filter(r => !INTERNAL_DOCS.has('game/' + r.id)).map(r => (
        r.id === 'state' ? { id: r.id, data: sanitizePublicState(r.data, now) } : r
      ));
    }
    return jsonRes({ rows, serverNow: now });
  }

  // Authenticated mutations
  const authUid = body.uid || request.headers.get('x-dodge-uid');
  const authToken = body.token || request.headers.get('x-dodge-token');
  if (!(await verifyUidToken(secret, authUid, authToken))) {
    return jsonRes({ error: 'unauthorized' }, 401);
  }
  if (!checkRateLimit(uidBuckets, authUid, UID_RATE_LIMIT, RATE_WINDOW_MS, now)) {
    return jsonRes({ error: 'rate_limited' }, 429, { 'retry-after': '5' });
  }

  /* ---- Equip Unlockable Reward (strict ownership check -> 403 on unowned) ---- */
  if (op === 'equip_reward') {
    const sc = (await dbGet(db, 'scores/' + authUid)) || defaultScoreDoc(authUid, body.nick);
    const owned = ownedRewardsFor(sc.achievements, sc.claimed);
    const eq = Object.assign({ skin: 'default', trail: 'default', aura: 'none', title: '' }, sc.equipped);

    if (body.skin !== undefined) {
      const v = String(body.skin || 'default');
      if (!owned.skins.has(v)) return jsonRes({ error: 'reward_not_unlocked', slot: 'skin', id: v }, 403);
      eq.skin = v;
    }
    if (body.trail !== undefined) {
      const v = String(body.trail || 'default');
      if (!owned.trails.has(v)) return jsonRes({ error: 'reward_not_unlocked', slot: 'trail', id: v }, 403);
      eq.trail = v;
    }
    if (body.aura !== undefined) {
      const v = String(body.aura || 'none');
      if (!owned.auras.has(v)) return jsonRes({ error: 'reward_not_unlocked', slot: 'aura', id: v }, 403);
      eq.aura = v;
    }
    if (body.title !== undefined) {
      const v = String(body.title || '');
      if (!owned.titles.has(v)) return jsonRes({ error: 'reward_not_unlocked', slot: 'title', id: v }, 403);
      eq.title = v;
    }
    sc.equipped = eq;
    await dbSet(db, 'scores/' + authUid, sc);

    // Sync title to active queue / game state if present
    const [q, st] = await Promise.all([dbGet(db, 'queue/' + authUid), dbGet(db, 'game/state')]);
    const syncWrites = [];
    if (q) { q.title = eq.title; syncWrites.push(dbSet(db, 'queue/' + authUid, q)); }
    if (st) {
      let dirty = false;
      if (st.runner === authUid && !st.done) { st.title = eq.title; dirty = true; }
      if (st.last && st.last.uid === authUid) { st.last.title = eq.title; dirty = true; }
      if (dirty) syncWrites.push(dbSet(db, 'game/state', st));
    }
    if (syncWrites.length) await Promise.all(syncWrites);

    return jsonRes({ ok: true, equipped: eq, serverNow: now });
  }

  /* ---- Claim quest rewards (quest must be complete; idempotent) ---- */
  if (op === 'claim_reward') {
    const ids = (Array.isArray(body.ids) ? body.ids : [body.id]).slice(0, 16).map(x => String(x || ''));
    if (!ids.length || ids.some(id => !hasOwn(ACH_REWARDS, id))) return jsonRes({ error: 'invalid_reward' }, 400);
    const sc = await dbGet(db, 'scores/' + authUid);
    if (!sc) return jsonRes({ error: 'quest_not_complete' }, 403);
    if (!sc.claimed || typeof sc.claimed !== 'object') sc.claimed = {};
    const newly = [];
    for (const id of ids) {
      if (!hasOwn(sc.achievements, id) || !sc.achievements[id]) return jsonRes({ error: 'quest_not_complete', id }, 403);
      if (!hasOwn(sc.claimed, id) || !sc.claimed[id]) { sc.claimed[id] = now; newly.push(id); }
    }
    if (newly.length) await dbSet(db, 'scores/' + authUid, sc);
    return jsonRes({ ok: true, claimed: sc.claimed, newly, serverNow: now });
  }

  /* ---- Queue operations ---- */
  if (op === 'queue_join') {
    const nick = sanitizeNick(body.nick);
    if (!nick) return jsonRes({ error: 'invalid_nick' }, 400);
    const mode = sanitizeMode(body.mode);
    const tab = String(body.tab || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 't';
    const [existing, sc] = await Promise.all([dbGet(db, 'queue/' + authUid), dbGet(db, 'scores/' + authUid)]);
    const title = (sc && sc.equipped && sc.equipped.title) || '';
    const entry = {
      uid: authUid, nick, title, mode, tab,
      at: (existing && Number.isFinite(existing.at)) ? existing.at : now,
      hb: clampInt(body.hb, 1, 1e9, 1),
      lastHbAt: now
    };
    await dbSet(db, 'queue/' + authUid, entry);
    return jsonRes({ ok: true, entry, serverNow: now });
  }

  if (op === 'queue_leave') {
    await dbDelete(db, 'queue/' + authUid);
    return jsonRes({ ok: true, serverNow: now });
  }

  /* ---- Turn Advance ---- */
  if (op === 'advance') {
    if (!(await acquireLock(db, authUid, now, 3500))) {
      return jsonRes({ ok: true, advanced: false, reason: 'locked', serverNow: now });
    }

    try {
      const st = await dbGet(db, 'game/state');
      if (st && !isTurnOver(st, now)) {
        return jsonRes({ ok: true, advanced: false, state: sanitizePublicState(st, now), serverNow: now });
      }

      let lastInfo = st && st.last ? st.last : null;
      let rev = ((st && Number(st.rev)) || 0) + 1;
      if (st && st.runner && !st.done) {
        const fin = await finalizeTurnInternal(db, st, now, false);
        lastInfo = fin.state.last;
        rev = fin.state.rev + 1;
      }

      const qRows = await dbList(db, 'queue');
      const fresh = [];
      for (const r of qRows) {
        const q = r.data;
        if (!q || !isValidUid(q.uid)) { await dbDelete(db, 'queue/' + r.id); continue; }
        const lastAt = q.lastHbAt || q.at || 0;
        if (now - lastAt > QUEUE_PURGE_MS) { await dbDelete(db, 'queue/' + r.id); continue; }
        if (now - lastAt <= QUEUE_STALE_MS) fresh.push(q);
      }
      fresh.sort((a, b) => (a.at - b.at) || (a.uid < b.uid ? -1 : 1));

      if (!fresh.length) {
        const curState = await dbGet(db, 'game/state');
        return jsonRes({ ok: true, advanced: false, state: sanitizePublicState(curState, now), serverNow: now });
      }

      const nx = fresh[0];
      const mode = sanitizeMode(nx.mode);
      const dur = lenFor(fresh.length - 1);
      const startsAt = now + TURN_COUNTDOWN_MS;
      const endsAt = startsAt + dur;
      const turnNonce = randomHex(12);
      const turnToken = await makeTurnToken(secret, nx.uid, rev, mode, turnNonce);

      let startLevel = 1;
      let seed = hashStr('lr-' + dayKey(now));
      if (mode === 'relay') {
        const relay = await getOrInitRelay(db, now);
        startLevel = Math.max(1, Number(relay.relayLevel) || 1);
        seed = relay.seed || hashStr('lr-relay-v2');
      }

      const newState = {
        runner: nx.uid,
        nick: sanitizeNick(nx.nick) || 'Player',
        title: nx.title || '',
        tab: nx.tab || 't',
        mode, dur,
        issuedAt: now, startsAt, endsAt,
        lastHbAt: now, disconnectedAt: null,
        cleared: 0, startLevel, n: startLevel,
        hb: 1, done: false, rev, seed, last: lastInfo
      };

      const sessionDoc = {
        uid: nx.uid, rev, mode, turnToken,
        startsAt, endsAt, levelStartedAt: startsAt,
        currentLevel: startLevel, cleared: 0,
        flawlessStreak: 0, turnDeaths: 0, razorTurnCount: 0, turnClutchTypes: [],
        issuedAt: now
      };

      await dbSet(db, 'game/session', sessionDoc);
      await dbSet(db, 'game/state', newState);
      await dbDelete(db, 'queue/' + nx.uid);

      const resPayload = { ok: true, advanced: true, state: sanitizePublicState(newState, now), serverNow: now };
      if (nx.uid === authUid) resPayload.turnToken = turnToken;
      return jsonRes(resPayload);
    } finally {
      await dbDelete(db, 'game/lock');
    }
  }

  /* ---- Resume within 10s Grace Window ---- */
  if (op === 'resume') {
    const st = await dbGet(db, 'game/state');
    const sess = await dbGet(db, 'game/session');
    if (!st || !sess || st.done || st.runner !== authUid || sess.uid !== authUid || sess.rev !== st.rev) {
      return jsonRes({ error: 'no_active_turn', state: sanitizePublicState(st, now), serverNow: now }, 404);
    }
    if (isTurnOver(st, now)) {
      const fin = await finalizeTurnInternal(db, st, now, false);
      return jsonRes({ error: 'turn_expired', state: sanitizePublicState(fin.state, now), serverNow: now }, 410);
    }
    const tab = String(body.tab || st.tab || 't').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 't';
    st.tab = tab;
    st.disconnectedAt = null;
    st.lastHbAt = now;
    st.hb = (Number(st.hb) || 0) + 1;
    await dbSet(db, 'game/state', st);
    return jsonRes({ ok: true, state: sanitizePublicState(st, now), turnToken: sess.turnToken, serverNow: now });
  }

  /* ---- Runner Heartbeat ---- */
  if (op === 'heartbeat') {
    const st = await dbGet(db, 'game/state');
    const sess = await dbGet(db, 'game/session');
    if (!st || !sess || st.done || st.runner !== authUid || sess.rev !== st.rev) {
      return jsonRes({ error: 'no_active_turn', state: sanitizePublicState(st, now), serverNow: now }, 409);
    }
    if (!(await verifyTurnToken(secret, authUid, st.rev, st.mode, body.turnToken)) || !timingSafeEqual(sess.turnToken, String(body.turnToken || ''))) {
      return jsonRes({ error: 'invalid_turn_token', serverNow: now }, 403);
    }
    if (isTurnOver(st, now)) {
      const fin = await finalizeTurnInternal(db, st, now, false);
      return jsonRes({ error: 'turn_expired', state: sanitizePublicState(fin.state, now), serverNow: now }, 410);
    }
    st.lastHbAt = now;
    st.disconnectedAt = null;
    st.hb = (Number(st.hb) || 0) + 1;
    await dbSet(db, 'game/state', st);
    return jsonRes({ ok: true, serverNow: now });
  }

  /* ---- Disconnect Mark ---- */
  if (op === 'disconnect') {
    const st = await dbGet(db, 'game/state');
    const sess = await dbGet(db, 'game/session');
    if (!st || !sess || st.done || st.runner !== authUid || sess.rev !== st.rev) {
      return jsonRes({ ok: true, ignored: true, serverNow: now });
    }
    if (!(await verifyTurnToken(secret, authUid, st.rev, st.mode, body.turnToken)) || !timingSafeEqual(sess.turnToken, String(body.turnToken || ''))) {
      return jsonRes({ error: 'invalid_turn_token', serverNow: now }, 403);
    }
    if (!st.disconnectedAt) {
      st.disconnectedAt = now;
      await dbSet(db, 'game/state', st);
    }
    return jsonRes({ ok: true, graceEndsAt: st.disconnectedAt + RECONNECT_GRACE_MS, serverNow: now });
  }

  /* ---- Verified Level Clear + Clutches & Achievements ---- */
  if (op === 'level_clear') {
    const st = await dbGet(db, 'game/state');
    const sess = await dbGet(db, 'game/session');
    if (!st || !sess || st.done || st.runner !== authUid || sess.uid !== authUid || sess.rev !== st.rev) {
      return jsonRes({ error: 'invalid_turn_session', state: sanitizePublicState(st, now), serverNow: now }, 403);
    }
    if (!(await verifyTurnToken(secret, authUid, st.rev, st.mode, body.turnToken)) || !timingSafeEqual(sess.turnToken, String(body.turnToken || ''))) {
      return jsonRes({ error: 'invalid_turn_token', serverNow: now }, 403);
    }
    if (now > st.endsAt + 2500) {
      const fin = await finalizeTurnInternal(db, st, now, false);
      return jsonRes({ error: 'turn_expired', state: sanitizePublicState(fin.state, now), serverNow: now }, 410);
    }

    const claimedLevel = clampInt(body.level, 1, 100000, -1);
    if (claimedLevel !== sess.currentLevel || claimedLevel !== st.n) {
      return jsonRes({ error: 'non_monotonic_level', expected: sess.currentLevel, state: sanitizePublicState(st, now), serverNow: now }, 400);
    }

    const tel = body.telemetry && typeof body.telemetry === 'object' ? body.telemetry : {};
    const clearMs = clampInt(body.clearMs, 0, 600000, -1);
    const levelW = clampInt(tel.w, 16, 260, 48);
    const frames = clampInt(tel.frames, 0, 1000000, 0);
    const deaths = clampInt(tel.deaths, 0, 10000, 0);
    const cfg = tel.cfg && typeof tel.cfg === 'object' ? tel.cfg : {};
    const mods = Array.isArray(tel.mods) ? tel.mods : [];
    const levelClutches = sanitizeClutchesList(tel.clutches, cfg);

    const minMs = minTheoreticalClearMs(claimedLevel, levelW, cfg);
    const serverElapsedMs = Math.max(0, now - Math.max(sess.startsAt, sess.levelStartedAt));

    if (clearMs < minMs) return jsonRes({ error: 'clear_too_fast', minMs, clearMs, state: sanitizePublicState(st, now), serverNow: now }, 400);
    if (serverElapsedMs < Math.floor(minMs * 0.75)) return jsonRes({ error: 'server_elapsed_too_fast', minMs, serverElapsedMs, state: sanitizePublicState(st, now), serverNow: now }, 400);
    if (frames < Math.floor(minMs * 0.06)) return jsonRes({ error: 'invalid_telemetry_frames', state: sanitizePublicState(st, now), serverNow: now }, 400);

    const nextLevel = claimedLevel + 1;
    st.cleared = (Number(st.cleared) || 0) + 1;
    st.n = nextLevel;
    st.lastHbAt = now;
    st.disconnectedAt = null;
    st.hb = (Number(st.hb) || 0) + 1;

    sess.cleared = st.cleared;
    sess.currentLevel = nextLevel;
    sess.levelStartedAt = now;

    const nick = st.nick || 'Player';
    const sc = Object.assign(defaultScoreDoc(authUid, nick), (await dbGet(db, 'scores/' + authUid)) || {});
    sc.uid = authUid;
    sc.nick = nick;

    const newlyUnlocked = evaluateLevelAchievements(sc, sess, st, claimedLevel, deaths, levelClutches, cfg, mods, now);

    await dbSet(db, 'game/session', sess);
    await dbSet(db, 'game/state', st);

    let relayUpdate = null;
    let levelRank = null;

    if (st.mode === 'time_attack') {
      const ltDoc = (await dbGet(db, 'game/level_times')) || { levels: {}, updatedAt: now };
      if (!ltDoc.levels || typeof ltDoc.levels !== 'object') ltDoc.levels = {};
      const lk = String(claimedLevel);
      const list = Array.isArray(ltDoc.levels[lk]) ? ltDoc.levels[lk].slice() : [];
      const existingIdx = list.findIndex(e => e.uid === authUid);
      if (existingIdx >= 0) {
        const curEntry = list[existingIdx];
        if (clearMs < curEntry.ms || (clearMs === curEntry.ms && deaths < (Number(curEntry.deaths) || 0))) {
          list[existingIdx] = { uid: authUid, nick, ms: clearMs, deaths, at: now };
        } else {
          list[existingIdx] = Object.assign({}, curEntry, { nick });
        }
      } else {
        list.push({ uid: authUid, nick, ms: clearMs, deaths, at: now });
      }
      list.sort((a, b) => (a.ms - b.ms) || ((Number(a.deaths) || 0) - (Number(b.deaths) || 0)) || (a.at - b.at));
      ltDoc.levels[lk] = list.slice(0, 25);
      ltDoc.updatedAt = now;
      await dbSet(db, 'game/level_times', ltDoc);
      levelRank = ltDoc.levels[lk].findIndex(e => e.uid === authUid) + 1;

      const prevLv = Math.max(1, Number(sc.level) || 1);
      if (nextLevel > prevLv) {
        sc.level = nextLevel;
        sc.levelAt = now;
      } else {
        sc.level = prevLv;
      }
      sc.levelBestMs = Object.assign({}, sc.levelBestMs);
      if (!sc.levelBestMs[lk] || clearMs < sc.levelBestMs[lk]) sc.levelBestMs[lk] = clearMs;
    }

    if (st.mode === 'relay') {
      const relay = await getOrInitRelay(db, now);
      if (nextLevel > (Number(relay.relayLevel) || 1)) relay.relayLevel = nextLevel;
      relay.totalClears = (Number(relay.totalClears) || 0) + 1;
      relay.lastRunner = { uid: authUid, nick, at: now };
      relay.updatedAt = now;
      if (!relay.milestones || typeof relay.milestones !== 'object') relay.milestones = {};

      let unlockedMilestone = null;
      if (isRelayMilestone(nextLevel) && !relay.milestones[String(nextLevel)]) {
        relay.milestones[String(nextLevel)] = { level: nextLevel, uid: authUid, nick, at: now };
        unlockedMilestone = nextLevel;
      }
      await dbSet(db, 'game/relay', relay);
      relayUpdate = { relayLevel: relay.relayLevel, totalClears: relay.totalClears, unlockedMilestone };

      sc.relayCleared = (Number(sc.relayCleared) || 0) + 1;
      sc.relayMilestones = Array.isArray(sc.relayMilestones) ? sc.relayMilestones : [];
      if (unlockedMilestone && !sc.relayMilestones.includes(unlockedMilestone)) sc.relayMilestones.push(unlockedMilestone);
    }

    await dbSet(db, 'scores/' + authUid, sc);

    return jsonRes({
      ok: true,
      cleared: st.cleared,
      n: st.n,
      clearMs,
      levelRank,
      relay: relayUpdate,
      unlocked: newlyUnlocked,
      achievements: sc.achievements,
      claimed: sc.claimed || {},
      clutches: sc.clutches,
      state: sanitizePublicState(st, now),
      serverNow: now
    });
  }

  /* ---- End Turn ---- */
  if (op === 'end_turn') {
    const st = await dbGet(db, 'game/state');
    const sess = await dbGet(db, 'game/session');
    if (!st || st.done || st.runner !== authUid) return jsonRes({ ok: true, alreadyDone: true, state: sanitizePublicState(st, now), serverNow: now });
    if (!sess || sess.rev !== st.rev || !(await verifyTurnToken(secret, authUid, st.rev, st.mode, body.turnToken)) || !timingSafeEqual(sess.turnToken, String(body.turnToken || ''))) {
      return jsonRes({ error: 'invalid_turn_token', serverNow: now }, 403);
    }
    const fin = await finalizeTurnInternal(db, st, now, !!body.manual);
    return jsonRes({ ok: true, state: sanitizePublicState(fin.state, now), score: fin.score, serverNow: now });
  }

  /* ---- Daily Dash: one fixed level per UTC day, fastest clear wins ---- */
  if (op === 'daily_submit') {
    const day = String(body.day || '');
    // a run that started just before midnight UTC may land just after it
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || (day !== dayKey(now) && day !== dayKey(now - 20 * 60000))) {
      return jsonRes({ error: 'wrong_day', day: dayKey(now), serverNow: now }, 400);
    }
    const tel = body.telemetry && typeof body.telemetry === 'object' ? body.telemetry : {};
    const ms = clampInt(body.ms, 0, DAILY_MAX_MS, -1);
    const deaths = clampInt(body.deaths, 0, 10000, 0);
    const frames = clampInt(tel.frames, 0, 10000000, 0);
    const cfg = tel.cfg && typeof tel.cfg === 'object' ? tel.cfg : {};
    const n = 10 + (hashStr('dash:' + day) % 17);
    const minMs = minTheoreticalClearMs(n, clampInt(tel.w, 16, 260, 48), cfg);
    if (ms < 0 || ms < minMs) return jsonRes({ error: 'clear_too_fast', minMs, ms, serverNow: now }, 400);
    if (frames < Math.floor(minMs * 0.06)) return jsonRes({ error: 'invalid_telemetry_frames', serverNow: now }, 400);

    const cur = (await dbGet(db, 'scores/' + authUid)) || null;
    const nick = sanitizeNick(body.nick) || (cur && cur.nick) || 'Player';
    const sc = Object.assign(defaultScoreDoc(authUid, nick), cur || {});
    sc.uid = authUid; sc.nick = nick;
    const prev = sc.daily && sc.daily.d === day ? sc.daily : null;
    const better = !prev || ms < prev.ms || (ms === prev.ms && deaths < (Number(prev.deaths) || 0));
    if (better) sc.daily = { d: day, ms, deaths, at: now };
    await dbSet(db, 'scores/' + authUid, sc);

    const sRows = await dbList(db, 'scores');
    let rank = 1;
    for (const r of sRows) {
      const o = r.data;
      if (!o || o.uid === authUid || !o.daily || o.daily.d !== day) continue;
      const om = Number(o.daily.ms) || Infinity, od = Number(o.daily.deaths) || 0;
      if (om < sc.daily.ms || (om === sc.daily.ms && od < (Number(sc.daily.deaths) || 0))) rank++;
    }
    return jsonRes({ ok: true, improved: better, rank, score: sc, serverNow: now });
  }

  /* ---- Nickname Sync ---- */
  if (op === 'sync_nick') {
    const nick = sanitizeNick(body.nick);
    if (!nick) return jsonRes({ error: 'invalid_nick' }, 400);
    const [sc, q, lv, st, lt, rel] = await Promise.all([
      dbGet(db, 'scores/' + authUid), dbGet(db, 'queue/' + authUid), dbGet(db, 'levels/' + authUid),
      dbGet(db, 'game/state'), dbGet(db, 'game/level_times'), dbGet(db, 'game/relay')
    ]);
    const writes = [];
    if (sc) { sc.nick = nick; writes.push(dbSet(db, 'scores/' + authUid, sc)); }
    if (q) { q.nick = nick; writes.push(dbSet(db, 'queue/' + authUid, q)); }
    if (lv) { lv.nick = nick; writes.push(dbSet(db, 'levels/' + authUid, lv)); }
    if (st) {
      let dirty = false;
      if (st.runner === authUid && !st.done) { st.nick = nick; dirty = true; }
      if (st.last && st.last.uid === authUid) { st.last.nick = nick; dirty = true; }
      if (dirty) writes.push(dbSet(db, 'game/state', st));
    }
    if (lt && lt.levels) {
      let dirty = false;
      for (const k of Object.keys(lt.levels)) {
        for (const e of (lt.levels[k] || [])) if (e.uid === authUid && e.nick !== nick) { e.nick = nick; dirty = true; }
      }
      if (dirty) writes.push(dbSet(db, 'game/level_times', lt));
    }
    if (rel) {
      let dirty = false;
      if (rel.lastRunner && rel.lastRunner.uid === authUid && rel.lastRunner.nick !== nick) { rel.lastRunner.nick = nick; dirty = true; }
      if (rel.milestones) {
        for (const k of Object.keys(rel.milestones)) {
          if (rel.milestones[k] && rel.milestones[k].uid === authUid && rel.milestones[k].nick !== nick) { rel.milestones[k].nick = nick; dirty = true; }
        }
      }
      if (dirty) writes.push(dbSet(db, 'game/relay', rel));
    }
    await Promise.all(writes);
    return jsonRes({ ok: true, nick, serverNow: now });
  }

  /* ---- Community Levels Publish ---- */
  if (op === 'levels_set') {
    const res = validateCommunityLevelsDoc(authUid, body.nick, body.items);
    if (res.error) return jsonRes({ error: res.error }, 400);
    await dbSet(db, 'levels/' + authUid, res.data);
    return jsonRes({ ok: true, data: res.data, serverNow: now });
  }

  /* ---- Legacy Compatibility Guard ---- */
  if (op === 'set' || op === 'update' || op === 'delete' || op === 'acquire') {
    const p = parsePath(body.path);
    if (!p || !p.id) return jsonRes({ error: 'invalid_path' }, 400);
    if (p.col === 'scores' || p.col === 'game') return jsonRes({ error: 'direct_write_forbidden' }, 403);
    if (p.id !== authUid) return jsonRes({ error: 'forbidden_other_user' }, 403);
    if (op === 'delete') { await dbDelete(db, p.path); return jsonRes({ ok: true, serverNow: now }); }
    if (p.col === 'levels') {
      const res = validateCommunityLevelsDoc(authUid, body.data && body.data.nick, body.data && body.data.items);
      if (res.error) return jsonRes({ error: res.error }, 400);
      await dbSet(db, p.path, res.data);
      return jsonRes({ ok: true, serverNow: now });
    }
    if (p.col === 'queue') {
      const d = body.data || {};
      const nick = sanitizeNick(d.nick);
      if (!nick) return jsonRes({ error: 'invalid_nick' }, 400);
      // Join time is server-owned: trusting a client `at` let players backdate themselves to the front of the queue.
      const [existing, scDoc] = await Promise.all([dbGet(db, p.path), dbGet(db, 'scores/' + authUid)]);
      const entry = {
        uid: authUid, nick, title: (scDoc && scDoc.equipped && scDoc.equipped.title) || '', mode: sanitizeMode(d.mode),
        tab: String(d.tab || 't').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 16) || 't',
        at: (existing && Number.isFinite(existing.at)) ? existing.at : now,
        hb: clampInt(d.hb, 1, 1e9, 1), lastHbAt: now
      };
      await dbSet(db, p.path, entry);
      return jsonRes({ ok: true, serverNow: now });
    }
  }

  return jsonRes({ error: 'unknown_op' }, 400);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/db') {
      try {
        return await handleApi(request, env);
      } catch (err) {
        console.error('api/db error:', err);
        return jsonRes({ error: 'internal_error' }, 500);
      }
    }
    if (env && env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  }
};

export {
  handleApi,
  minTheoreticalClearMs,
  sanitizeNick,
  validateCommunityLevelsDoc,
  getGraceInfo,
  isTurnOver,
  makeUidToken,
  verifyUidToken,
  makeTurnToken,
  verifyTurnToken,
  ACH_REWARDS,
  RECONNECT_GRACE_MS,
  IP_RATE_LIMIT,
  UID_RATE_LIMIT
};