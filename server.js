/**
 * StudyAI — Local Auth Backend
 * Node.js built-ins only (http, crypto, fs, path, url).
 * No npm install required.
 *
 * What this covers
 *   POST /api/auth/signup      – register (hashed password, persisted)
 *   POST /api/auth/login       – verify credentials, start session
 *   POST /api/auth/logout      – destroy session
 *   GET  /api/auth/me          – return current user or 401
 *   GET  /                     – serve index.html (the wired frontend)
 *   GET  *                     – serve any static file in /public
 *
 * What this intentionally does NOT cover
 *   - HTTPS / TLS  (add a reverse-proxy like Caddy for that)
 *   - Email verification / password-reset flows
 *   - Rate-limiting (trivial to add; excluded to keep this readable)
 *   - Production DB (swap JSON files for Postgres / Supabase trivially)
 */

const http   = require('http');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const url    = require('url');

// ─── config ──────────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const PUBLIC_DIR  = path.join(__dirname, 'public');
const DATA_DIR    = path.join(__dirname, 'data');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const NOTES_FILE  = path.join(DATA_DIR, 'notes.json');
const PREFS_FILE  = path.join(DATA_DIR, 'preferences.json');
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

// ─── persistence helpers ──────────────────────────────────────────────────────
function loadJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// In-memory sessions  {token -> {userId, email, name, expires}}
// (restart clears sessions → users just log in again; fine for a demo)
const sessions = new Map();

// ─── password helpers ─────────────────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

// ─── session helpers ──────────────────────────────────────────────────────────
function createSession(user) {
  const token   = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + SESSION_TTL;
  sessions.set(token, { userId: user.id, email: user.email, name: user.name, expires });
  return token;
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/studyai_token=([a-f0-9]{64})/);
  if (!match) return null;
  const session = sessions.get(match[1]);
  if (!session || session.expires < Date.now()) { sessions.delete(match[1]); return null; }
  return { ...session, token: match[1] };
}

function setCookieHeader(token, maxAge) {
  return `studyai_token=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

// ─── MIME types ───────────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js'  : 'application/javascript',
  '.css' : 'text/css',
  '.json': 'application/json',
  '.png' : 'image/png',
  '.jpg' : 'image/jpeg',
  '.svg' : 'image/svg+xml',
  '.ico' : 'image/x-icon',
};

// ─── body parser ─────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 8192) req.destroy(); });
    req.on('end',  () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

// ─── response helpers ─────────────────────────────────────────────────────────
function json(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(body);
}

// ─── route handlers ───────────────────────────────────────────────────────────
async function handleSignup(req, res) {
  const { name, email, password } = await readBody(req);

  if (!name || !email || !password)
    return json(res, 400, { error: 'Name, email and password are required.' });

  if (password.length < 8)
    return json(res, 400, { error: 'Password must be at least 8 characters.' });

  const users = loadJSON(USERS_FILE, []);
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return json(res, 409, { error: 'An account with that email already exists.' });

  const user = {
    id:        crypto.randomUUID(),
    name:      name.trim(),
    email:     email.toLowerCase().trim(),
    password:  hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveJSON(USERS_FILE, users);

  const token = createSession(user);
  json(res, 201,
    { ok: true, user: { id: user.id, name: user.name, email: user.email } },
    { 'Set-Cookie': setCookieHeader(token, SESSION_TTL / 1000) }
  );
}

async function handleLogin(req, res) {
  const { email, password } = await readBody(req);

  if (!email || !password)
    return json(res, 400, { error: 'Email and password are required.' });

  const users = loadJSON(USERS_FILE, []);
  const user  = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (!user || !verifyPassword(password, user.password))
    return json(res, 401, { error: 'Invalid email or password.' });

  const token = createSession(user);
  json(res, 200,
    { ok: true, user: { id: user.id, name: user.name, email: user.email } },
    { 'Set-Cookie': setCookieHeader(token, SESSION_TTL / 1000) }
  );
}

function handleLogout(req, res) {
  const session = getSession(req);
  if (session) sessions.delete(session.token);
  json(res, 200,
    { ok: true },
    { 'Set-Cookie': setCookieHeader('', 0) }  // clear cookie
  );
}

function handleMe(req, res) {
  const session = getSession(req);
  if (!session) return json(res, 401, { error: 'Not authenticated.' });
  json(res, 200, { ok: true, user: { id: session.userId, name: session.name, email: session.email } });
}

// ─── static file server ───────────────────────────────────────────────────────
function serveStatic(req, res) {
  let filePath = path.join(PUBLIC_DIR, url.parse(req.url).pathname);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory())
    filePath = path.join(filePath, 'index.html');

  if (!fs.existsSync(filePath)) {
    res.writeHead(404); res.end('Not found'); return;
  }
  const ext  = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(filePath).pipe(res);
}

// ─── router ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  // CORS for local dev (optional; remove in production behind same origin)
  res.setHeader('Access-Control-Allow-Origin',  req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const { pathname } = url.parse(req.url);

  try {
    if (pathname === '/api/auth/signup' && req.method === 'POST') return await handleSignup(req, res);
    if (pathname === '/api/auth/login'  && req.method === 'POST') return await handleLogin(req, res);
    if (pathname === '/api/auth/logout' && req.method === 'POST') return handleLogout(req, res);
    if (pathname === '/api/auth/me'          && req.method === 'GET')    return handleMe(req, res);
    if (pathname === '/api/preferences'        && req.method === 'GET')    return handleGetPreferences(req, res);
    if (pathname === '/api/preferences'        && req.method === 'POST')   return await handleSavePreferences(req, res);
    if (pathname === '/api/notes'              && req.method === 'GET')    return handleGetNotes(req, res);
    if (pathname === '/api/notes'              && req.method === 'POST')   return await handleSaveNotes(req, res);
    if (pathname.startsWith('/api/notes/')     && req.method === 'DELETE') return await handleDeleteNote(req, res, pathname.replace('/api/notes/', ''));
    if (pathname === '/api/account'            && req.method === 'DELETE') return handleDeleteAccount(req, res);
    return serveStatic(req, res);
  } catch (err) {
    console.error('Unhandled error:', err);
    json(res, 500, { error: 'Internal server error.' });
  }
});

server.listen(PORT, () => {
  console.log(`\n  StudyAI backend running → http://localhost:${PORT}\n`);
  console.log(`  Users file : ${USERS_FILE}`);
  console.log(`  Sessions   : in-memory (cleared on restart)\n`);
});

// ─── helpers shared by new routes ─────────────────────────────────────────────
function requireAuth(req, res) {
  const session = getSession(req);
  if (!session) { json(res, 401, { error: 'Not authenticated.' }); return null; }
  return session;
}

// ─── T5: preferences ──────────────────────────────────────────────────────────
function handleGetPreferences(req, res) {
  const session = requireAuth(req, res); if (!session) return;
  const all   = loadJSON(PREFS_FILE, {});
  const prefs = all[session.userId] || { notifications: true, reminders: false, aiSuggestions: true };
  json(res, 200, prefs);
}

async function handleSavePreferences(req, res) {
  const session = requireAuth(req, res); if (!session) return;
  const body  = await readBody(req);
  const all   = loadJSON(PREFS_FILE, {});
  all[session.userId] = {
    notifications: !!body.notifications,
    reminders:     !!body.reminders,
    aiSuggestions: !!body.aiSuggestions,
  };
  saveJSON(PREFS_FILE, all);
  json(res, 200, { ok: true });
}

// ─── T6: notes ────────────────────────────────────────────────────────────────
function handleGetNotes(req, res) {
  const session = requireAuth(req, res); if (!session) return;
  const all   = loadJSON(NOTES_FILE, {});
  const notes = all[session.userId] || [];
  json(res, 200, notes);
}

async function handleSaveNotes(req, res) {
  const session = requireAuth(req, res); if (!session) return;
  const body = await readBody(req);
  if (!Array.isArray(body)) return json(res, 400, { error: 'Expected an array of notes.' });
  const all = loadJSON(NOTES_FILE, {});
  all[session.userId] = body;
  saveJSON(NOTES_FILE, all);
  json(res, 200, { ok: true });
}

async function handleDeleteNote(req, res, noteId) {
  const session = requireAuth(req, res); if (!session) return;
  const id  = parseInt(noteId, 10);
  const all = loadJSON(NOTES_FILE, {});
  all[session.userId] = (all[session.userId] || []).filter(n => n.id !== id);
  saveJSON(NOTES_FILE, all);
  json(res, 200, { ok: true });
}

// ─── T7: account deletion ─────────────────────────────────────────────────────
function handleDeleteAccount(req, res) {
  const session = requireAuth(req, res); if (!session) return;
  const { userId, token } = session;

  // Remove from users.json
  const users = loadJSON(USERS_FILE, []);
  saveJSON(USERS_FILE, users.filter(u => u.id !== userId));

  // Remove preferences
  const prefs = loadJSON(PREFS_FILE, {});
  delete prefs[userId];
  saveJSON(PREFS_FILE, prefs);

  // Remove notes
  const notes = loadJSON(NOTES_FILE, {});
  delete notes[userId];
  saveJSON(NOTES_FILE, notes);

  // Destroy session
  sessions.delete(token);
  json(res, 200, { ok: true }, { 'Set-Cookie': setCookieHeader('', 0) });
}