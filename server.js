require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const compression = require('compression');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const helmet = require('helmet');
const multer = require('multer');
const nodemailer = require('nodemailer');
const session = require('express-session');
const sharp = require('sharp');

const app = express();
const port = Number(process.env.PORT || 3000);
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || (!isProduction ? crypto.randomBytes(48).toString('hex') : '');
const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const configuredOrigin = process.env.PUBLIC_ORIGIN ? new URL(process.env.PUBLIC_ORIGIN).origin : '';
const adminEmails = new Set((process.env.ADMIN_EMAILS || '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
const smtpHost = process.env.SMTP_HOST || '';
const smtpFrom = process.env.SMTP_FROM || '';
const smtpUser = process.env.SMTP_USER || '';
const smtpPass = process.env.SMTP_PASS || '';
const mailTransport = smtpHost && smtpFrom && smtpUser && smtpPass ? nodemailer.createTransport({
  host: smtpHost,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: smtpUser, pass: smtpPass },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 20000
}) : null;

if (!sessionSecret || (isProduction && sessionSecret.length < 32)) {
  throw new Error('Set SESSION_SECRET to a random value of at least 32 characters.');
}

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'streetfight.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    google_sub TEXT UNIQUE,
    password_hash TEXT,
    display_name TEXT NOT NULL,
    avatar_path TEXT,
    balance REAL NOT NULL DEFAULT 0 CHECK(balance >= 0),
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS admin_email_verifications (
    email TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    resend_after INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS fights (
    id TEXT PRIMARY KEY,
    league TEXT NOT NULL,
    start_time TEXT NOT NULL,
    fighter_a TEXT NOT NULL,
    fighter_b TEXT NOT NULL,
    is_live INTEGER NOT NULL DEFAULT 0,
    result_winner INTEGER CHECK(result_winner IN (0, 1) OR result_winner IS NULL),
    deleted_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS betting_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    start_time TEXT NOT NULL DEFAULT '22:00',
    end_time TEXT NOT NULL DEFAULT '00:00'
  );
  INSERT OR IGNORE INTO betting_settings (id) VALUES (1);
  CREATE TABLE IF NOT EXISTS bet_picks (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    fight_id TEXT NOT NULL REFERENCES fights(id),
    selection INTEGER NOT NULL CHECK(selection IN (0, 1)),
    amount REAL NOT NULL CHECK(amount > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'won', 'lost')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS balance_credits (
    id TEXT PRIMARY KEY,
    target_user_id TEXT NOT NULL REFERENCES users(id),
    admin_user_id TEXT NOT NULL REFERENCES users(id),
    amount REAL NOT NULL CHECK(amount > 0),
    currency TEXT NOT NULL DEFAULT 'USDT',
    entered_amount REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS analytics_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL CHECK(event_type IN ('page_view', 'signup_cta')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);
if (!db.pragma('table_info(fights)').some(column => column.name === 'result_winner')) {
  db.exec('ALTER TABLE fights ADD COLUMN result_winner INTEGER CHECK(result_winner IN (0, 1) OR result_winner IS NULL)');
}
if (!db.pragma('table_info(users)').some(column => column.name === 'email_verified')) {
  db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0');
}
if (!db.pragma('table_info(fights)').some(column => column.name === 'deleted_at')) {
  db.exec('ALTER TABLE fights ADD COLUMN deleted_at TEXT');
}
if (!db.pragma('table_info(balance_credits)').some(column => column.name === 'currency')) {
  db.exec("ALTER TABLE balance_credits ADD COLUMN currency TEXT NOT NULL DEFAULT 'USDT'");
}
if (!db.pragma('table_info(balance_credits)').some(column => column.name === 'entered_amount')) {
  db.exec('ALTER TABLE balance_credits ADD COLUMN entered_amount REAL NOT NULL DEFAULT 0');
}

class SqliteSessionStore extends session.Store {
  get(sid, callback) {
    try {
      const row = db.prepare('SELECT session, expires_at FROM sessions WHERE sid = ?').get(sid);
      if (!row) return callback(null, null);
      if (row.expires_at <= Date.now()) {
        db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(row.session));
    } catch (error) { callback(error); }
  }

  set(sid, value, callback) {
    try {
      const expiresAt = value.cookie?.expires ? new Date(value.cookie.expires).getTime() : Date.now() + 86400000;
      db.prepare('INSERT INTO sessions (sid, session, expires_at) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET session = excluded.session, expires_at = excluded.expires_at').run(sid, JSON.stringify(value), expiresAt);
      callback?.(null);
    } catch (error) { callback?.(error); }
  }

  destroy(sid, callback) {
    try { db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid); callback?.(null); }
    catch (error) { callback?.(error); }
  }

  touch(sid, value, callback) { this.set(sid, value, callback); }
}

app.disable('x-powered-by');
app.set('trust proxy', isProduction ? 1 : false);
app.use(helmet({
  strictTransportSecurity: isProduction ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://accounts.google.com/gsi/client'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https://lh3.googleusercontent.com'],
      connectSrc: ["'self'", 'https://accounts.google.com', 'https://oauth2.googleapis.com'],
      frameSrc: ["'self'", 'https://accounts.google.com'],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
}));
app.use(compression());
app.use((req, res, next) => {
  if (!isProduction || req.secure) return next();
  if (!configuredOrigin.startsWith('https://')) return res.status(503).type('text/plain').send('Set PUBLIC_ORIGIN to your HTTPS site URL before exposing this server.');
  res.redirect(308, new URL(req.originalUrl, configuredOrigin).toString());
});
app.use(express.json({ limit: '1mb' }));
app.use(session({
  store: new SqliteSessionStore(),
  name: 'sfb.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: isProduction, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use('/uploads', express.static(uploadDir, { maxAge: '1d', fallthrough: true }));
app.get('/assets/social-preview.png', async (_req, res, next) => {
  try {
    const svg = await fs.promises.readFile(path.join(__dirname, 'assets', 'social-preview.svg'));
    const png = await sharp(svg, { density: 144 }).resize(1200, 630, { fit: 'cover' }).png({ compressionLevel: 9 }).toBuffer();
    res.type('png').set('Cache-Control', 'public, max-age=86400').send(png);
  } catch (error) { next(error); }
});
app.use('/assets', express.static(path.join(__dirname, 'assets'), {
  maxAge: '1d',
  fallthrough: true,
  setHeaders(res, filePath) {
    if (path.basename(filePath) === 'auth-client.js') res.setHeader('Cache-Control', 'no-cache');
  }
}));

function originFor(req) { return configuredOrigin || new URL(`${req.protocol}://${req.get('host')}`).origin; }
async function sendHtml(req, res, file) {
  const html = await fs.promises.readFile(path.join(__dirname, file), 'utf8');
  res.type('html').send(html.replaceAll('__SITE_ORIGIN__', originFor(req)));
}

app.get('/', (req, res, next) => sendHtml(req, res, 'aurum-bet-v2.html').catch(next));
app.get(['/terms', '/terms/'], (req, res, next) => sendHtml(req, res, 'terms.html').catch(next));
app.get('/favicon.svg', (_req, res) => res.sendFile(path.join(__dirname, 'assets', 'favicon.svg'), { maxAge: '1d' }));
app.get('/robots.txt', (req, res) => res.type('text/plain').send(`User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /uploads/\nSitemap: ${originFor(req)}/sitemap.xml\n`));
app.get('/sitemap.xml', (req, res) => {
  const origin = originFor(req);
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${origin}/</loc></url><url><loc>${origin}/terms</loc></url></urlset>`);
});
app.get('/api/config', (_req, res) => res.json({ googleClientId }));

const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const analyticsLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false });
const adminLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 80, standardHeaders: 'draft-8', legacyHeaders: false });
const getUser = db.prepare('SELECT id, email, display_name, avatar_path, balance, role, email_verified, created_at FROM users WHERE id = ?');
const getUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const createUser = db.prepare('INSERT INTO users (id, email, google_sub, password_hash, display_name, role, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)');
const updateBootstrapRole = db.prepare("UPDATE users SET role = 'admin' WHERE email = ? AND email_verified = 1");
const demoteUnverifiedBootstrap = db.prepare("UPDATE users SET role = 'user' WHERE email = ? AND email_verified = 0");
const getEmailVerification = db.prepare('SELECT * FROM admin_email_verifications WHERE email = ?');
const removeEmailVerification = db.prepare('DELETE FROM admin_email_verifications WHERE email = ?');

function publicUser(user) {
  return { id: user.id, email: user.email, displayName: user.display_name, avatarUrl: user.avatar_path, balance: user.balance, role: user.role, createdAt: user.created_at };
}

function requireCsrf(req, res, next) {
  const token = req.get('x-csrf-token');
  const expected = req.session.csrfToken;
  if (!token || !expected || token.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
    return res.status(403).json({ error: 'Session de sécurité expirée. Recharge la page et réessaie.' });
  }
  next();
}

app.post('/api/analytics/events', analyticsLimit, requireCsrf, (req, res) => {
  if (req.body.consent !== true) return res.status(204).end();
  const eventType = req.body.eventType;
  if (!['page_view', 'signup_cta'].includes(eventType)) return res.status(400).json({ error: 'Événement invalide.' });
  db.prepare('INSERT INTO analytics_events (id, event_type) VALUES (?, ?)').run(crypto.randomUUID(), eventType);
  res.status(204).end();
});

function requireAuth(req, res, next) {
  const user = req.session.userId && getUser.get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Connecte-toi pour continuer.' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin' || (adminEmails.has(req.user.email) && !req.user.email_verified)) {
    if (adminEmails.has(req.user.email) && !req.user.email_verified) demoteUnverifiedBootstrap.run(req.user.email);
    return res.status(403).json({ error: 'Accès réservé aux administrateurs vérifiés.' });
  }
  next();
}

function createAccountId() { return `SFB-${crypto.randomUUID().replaceAll('-', '').toUpperCase()}`; }
function newAdminEmail(email) { return adminEmails.has(email) ? 'admin' : 'user'; }
function createRouteError(message, statusCode) { const error = new Error(message); error.statusCode = statusCode; return error; }
async function sendEmailVerification(email, displayName, passwordHash = null, userId = null) {
  if (!mailTransport) throw createRouteError('L’envoi du code e-mail n’est pas configuré. Ajoute les paramètres SMTP au fichier .env puis redémarre le serveur.', 503);
  const now = Date.now();
  const existing = getEmailVerification.get(email);
  if (existing && existing.resend_after > now) throw createRouteError('Un code vient déjà d’être envoyé. Attends une minute avant de le redemander.', 429);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const codeHash = await bcrypt.hash(code, 12);
  db.prepare(`INSERT INTO admin_email_verifications (email, user_id, display_name, password_hash, code_hash, expires_at, resend_after, attempts, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    ON CONFLICT(email) DO UPDATE SET user_id = excluded.user_id, display_name = excluded.display_name, password_hash = excluded.password_hash, code_hash = excluded.code_hash, expires_at = excluded.expires_at, resend_after = excluded.resend_after, attempts = 0, created_at = excluded.created_at`)
    .run(email, userId, displayName, passwordHash, codeHash, now + 10 * 60 * 1000, now + 60 * 1000, now);
  try {
    await mailTransport.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Ton code de vérification StreetFight Bet',
      text: `Ton code de vérification est : ${code}\n\nIl expire dans 10 minutes. Si tu n’as pas demandé ce code, ignore ce message.`,
      html: `<p>Ton code de vérification StreetFight Bet :</p><p style="font-size:28px;font-weight:bold;letter-spacing:8px">${code}</p><p>Il expire dans 10 minutes. Si tu n’as pas demandé ce code, ignore ce message.</p>`
    });
  } catch {
    removeEmailVerification.run(email);
    throw createRouteError('Le courriel de vérification n’a pas pu être envoyé. Vérifie la configuration SMTP.', 503);
  }
}
function startSession(req, user) {
  return new Promise((resolve, reject) => req.session.regenerate(error => {
    if (error) return reject(error);
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.save(saveError => saveError ? reject(saveError) : resolve());
  }));
}

app.get('/api/csrf', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.json({ token: req.session.csrfToken });
});

app.get('/api/me', (req, res) => {
  let user = req.session.userId && getUser.get(req.session.userId);
  if (!user) return res.json({ user: null });
  if (adminEmails.has(user.email)) {
    if (user.email_verified && user.role !== 'admin') updateBootstrapRole.run(user.email);
    if (!user.email_verified && user.role === 'admin') demoteUnverifiedBootstrap.run(user.email);
    user = getUser.get(user.id);
  }
  res.json({ user: publicUser(getUser.get(user.id)) });
});

app.post('/api/auth/register', authLimit, requireCsrf, async (req, res, next) => {
  if (String(req.body.website || '').trim()) return res.status(400).json({ error: 'Inscription invalide.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: 'Adresse courriel invalide.' });
  if (displayName.length < 2 || displayName.length > 32) return res.status(400).json({ error: 'Le nom doit contenir entre 2 et 32 caractères.' });
  if (password.length < 10 || Buffer.byteLength(password) > 72) return res.status(400).json({ error: 'Le mot de passe doit contenir entre 10 et 72 octets.' });
  const existingUser = getUserByEmail.get(email);
  if (adminEmails.has(email)) {
    if (existingUser?.role === 'admin' && existingUser.email_verified) return res.status(409).json({ error: 'Cette adresse possède déjà un compte administrateur.' });
    const pendingVerification = getEmailVerification.get(email);
    if (pendingVerification && pendingVerification.expires_at > Date.now()) {
      return res.status(202).json({ verificationRequired: true, email });
    }
    try {
      await sendEmailVerification(email, existingUser?.display_name || displayName, existingUser ? null : await bcrypt.hash(password, 12), existingUser?.id || null);
      return res.status(202).json({ verificationRequired: true, email });
    } catch (error) { return res.status(error.statusCode || 503).json({ error: error.message }); }
  }
  if (existingUser) return res.status(409).json({ error: 'Un compte existe déjà pour cette adresse.' });
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const pendingVerification = getEmailVerification.get(email);
    if (!pendingVerification || pendingVerification.expires_at <= Date.now()) {
      await sendEmailVerification(email, displayName, passwordHash);
    }
    res.status(202).json({ verificationRequired: true, email });
  } catch (error) { next(error); }
});

app.post('/api/auth/email-verification/verify', authLimit, requireCsrf, async (req, res, next) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Entre le code à 6 chiffres reçu par e-mail.' });
  const pending = getEmailVerification.get(email);
  if (!pending) return res.status(400).json({ error: 'Aucun code actif. Recommence l’inscription.' });
  if (pending.expires_at <= Date.now()) {
    removeEmailVerification.run(email);
    return res.status(410).json({ error: 'Le code a expiré. Demande-en un nouveau.' });
  }
  if (pending.attempts >= 5) {
    removeEmailVerification.run(email);
    return res.status(429).json({ error: 'Trop de tentatives. Demande un nouveau code.' });
  }
  if (!(await bcrypt.compare(code, pending.code_hash))) {
    const attempts = pending.attempts + 1;
    if (attempts >= 5) removeEmailVerification.run(email);
    else db.prepare('UPDATE admin_email_verifications SET attempts = ? WHERE email = ?').run(attempts, email);
    return res.status(400).json({ error: attempts >= 5 ? 'Trop de tentatives. Demande un nouveau code.' : 'Code incorrect.' });
  }
  try {
    let user;
    if (pending.user_id) {
      const existingUser = getUser.get(pending.user_id);
      if (!existingUser) { removeEmailVerification.run(email); return res.status(404).json({ error: 'Le compte à vérifier est introuvable.' }); }
      db.prepare("UPDATE users SET email_verified = 1, role = 'admin' WHERE id = ?").run(existingUser.id);
      user = getUser.get(existingUser.id);
    } else {
      const passwordHash = pending.password_hash;
      if (!passwordHash) return res.status(400).json({ error: 'Recommence l’inscription pour choisir un mot de passe.' });
      const id = createAccountId();
      createUser.run(id, email, null, passwordHash, pending.display_name, newAdminEmail(email), 1);
      user = getUser.get(id);
    }
    removeEmailVerification.run(email);
    await startSession(req, user);
    res.status(201).json({ user: publicUser(getUser.get(user.id)) });
  } catch (error) { next(error); }
});

app.post('/api/auth/email-verification/resend', authLimit, requireCsrf, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const pending = getEmailVerification.get(email);
  if (!pending) return res.status(400).json({ error: 'Aucun code à renvoyer. Recommence l’inscription.' });
  try {
    await sendEmailVerification(email, pending.display_name, pending.password_hash, pending.user_id);
    res.json({ sent: true, email });
  } catch (error) { res.status(error.statusCode || 503).json({ error: error.message }); }
});

app.post('/api/auth/login', authLimit, requireCsrf, async (req, res, next) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = getUserByEmail.get(email);
  if (!user?.password_hash || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Adresse courriel ou mot de passe incorrect.' });
  try {
    if (adminEmails.has(email)) {
      if (user.email_verified) updateBootstrapRole.run(email);
      else demoteUnverifiedBootstrap.run(email);
    }
    await startSession(req, getUser.get(user.id));
    res.json({ user: publicUser(getUser.get(user.id)) });
  } catch (error) { next(error); }
});

app.post('/api/auth/google', authLimit, requireCsrf, async (req, res, next) => {
  if (!googleClientId) return res.status(503).json({ error: 'La connexion Google doit être configurée par l’administrateur du site.' });
  try {
    const ticket = await new OAuth2Client(googleClientId).verifyIdToken({ idToken: String(req.body.credential || ''), audience: googleClientId });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload.email || !payload.email_verified) return res.status(401).json({ error: 'Le compte Google ne fournit pas une adresse vérifiée.' });
    const email = payload.email.toLowerCase();
    let user = db.prepare('SELECT * FROM users WHERE google_sub = ?').get(payload.sub);
    if (!user) {
      user = getUserByEmail.get(email);
      if (user && user.google_sub && user.google_sub !== payload.sub) return res.status(409).json({ error: 'Cette adresse est déjà liée à un autre compte Google.' });
      if (user) db.prepare('UPDATE users SET google_sub = ?, email_verified = 1 WHERE id = ?').run(payload.sub, user.id);
      else {
        const id = createAccountId();
        createUser.run(id, email, payload.sub, null, String(payload.name || email.split('@')[0]).slice(0, 32), newAdminEmail(email), 1);
        user = getUser.get(id);
      }
    }
    if (adminEmails.has(email)) updateBootstrapRole.run(email);
    await startSession(req, getUser.get(user.id));
    res.json({ user: publicUser(getUser.get(user.id)) });
  } catch (error) {
    if (error.message?.includes('Token used too late') || error.message?.includes('Invalid')) return res.status(401).json({ error: 'La connexion Google a expiré. Réessaie.' });
    next(error);
  }
});

app.post('/api/auth/logout', requireCsrf, (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie('sfb.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ ok: true });
  });
});

app.put('/api/me/profile', requireCsrf, requireAuth, (req, res) => {
  const displayName = String(req.body.displayName || '').trim();
  if (displayName.length < 2 || displayName.length > 32) return res.status(400).json({ error: 'Le nom doit contenir entre 2 et 32 caractères.' });
  db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, req.user.id);
  res.json({ user: publicUser(getUser.get(req.user.id)) });
});

const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => callback(null, ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype))
});

app.post('/api/me/avatar', requireCsrf, requireAuth, avatarUpload.single('avatar'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'Choisis une image PNG, JPG ou WebP de 2 Mo maximum.' });
  let optimized;
  try {
    optimized = await sharp(req.file.buffer, { limitInputPixels: 20000000 })
      .rotate()
      .resize(512, 512, { fit: 'cover', withoutEnlargement: true })
      .webp({ quality: 82, effort: 4 })
      .toBuffer();
  } catch {
    return res.status(400).json({ error: 'Le fichier choisi ne contient pas une image valide.' });
  }
  const filename = `${crypto.randomUUID()}.webp`;
  const avatarPath = `/uploads/${filename}`;
  try {
    await fs.promises.writeFile(path.join(uploadDir, filename), optimized, { flag: 'wx' });
    const previousPath = req.user.avatar_path;
    db.prepare('UPDATE users SET avatar_path = ? WHERE id = ?').run(avatarPath, req.user.id);
    if (previousPath?.startsWith('/uploads/')) {
      const previousName = path.basename(previousPath);
      if (previousName !== filename) await fs.promises.unlink(path.join(uploadDir, previousName)).catch(() => {});
    }
    res.json({ user: publicUser(getUser.get(req.user.id)) });
  } catch (error) { next(error); }
});

app.get('/api/fights', (_req, res) => {
  const rows = db.prepare('SELECT id, league AS lg, start_time AS t, fighter_a AS a, fighter_b AS b, is_live AS live, result_winner AS resultWinner FROM fights WHERE deleted_at IS NULL ORDER BY created_at DESC').all();
  res.json({ fights: rows.map(row => ({ ...row, s: 'combat', live: Number(row.live) })) });
});

function parisMinutes() {
  const parts = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Paris', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date());
  return Number(parts.find(part => part.type === 'hour').value) * 60 + Number(parts.find(part => part.type === 'minute').value);
}
function bettingWindow() {
  const settings = db.prepare('SELECT start_time AS startTime, end_time AS endTime FROM betting_settings WHERE id = 1').get();
  const toMinutes = value => Number(value.slice(0, 2)) * 60 + Number(value.slice(3));
  const now = parisMinutes(), start = toMinutes(settings.startTime), end = toMinutes(settings.endTime);
  const isOpen = start === end || (start < end ? now >= start && now < end : now >= start || now < end);
  const minutesUntilChange = start === end ? null : isOpen
    ? (end - now + 1440) % 1440 || 1440
    : (start - now + 1440) % 1440 || 1440;
  return { ...settings, isOpen, minutesUntilChange };
}
app.get('/api/betting-window', (_req, res) => res.json(bettingWindow()));
app.get('/api/me/wagers', requireAuth, (req, res) => {
  const picks = db.prepare(`SELECT p.id, p.selection, p.amount, p.status, p.created_at AS createdAt,
    f.fighter_a AS fighterA, f.fighter_b AS fighterB, f.result_winner AS resultWinner
    FROM bet_picks p JOIN fights f ON f.id = p.fight_id WHERE p.user_id = ? ORDER BY p.created_at DESC`).all(req.user.id);
  res.json({ picks });
});

app.post('/api/me/wager', requireCsrf, requireAuth, (req, res) => {
  const amount = Number(req.body.amount);
  const picks = req.body.picks;
  if (!Number.isFinite(amount) || amount <= 0 || amount > 100000 || !Array.isArray(picks) || picks.length < 1 || picks.length > 20) return res.status(400).json({ error: 'Mise ou sélection invalide.' });
  if (!bettingWindow().isOpen) return res.status(400).json({ error: 'Les paris sont fermés pour le moment.' });
  if (picks.some(pick => !pick || ![0, 1].includes(pick.selection) || !db.prepare('SELECT id FROM fights WHERE id = ? AND result_winner IS NULL AND deleted_at IS NULL').get(String(pick.matchId)))) {
    return res.status(400).json({ error: 'Un combat sélectionné n’est plus ouvert aux paris.' });
  }
  const total = amount * picks.length;
  const transaction = db.transaction(() => {
    const changed = db.prepare('UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?').run(total, req.user.id, total);
    if (!changed.changes) return false;
    const insertPick = db.prepare('INSERT INTO bet_picks (id, user_id, fight_id, selection, amount) VALUES (?, ?, ?, ?, ?)');
    for (const pick of picks) insertPick.run(crypto.randomUUID(), req.user.id, String(pick.matchId), pick.selection, amount);
    return true;
  });
  if (!transaction()) return res.status(400).json({ error: 'Solde insuffisant.' });
  res.json({ user: publicUser(getUser.get(req.user.id)) });
});

app.use('/api/admin', adminLimit, requireAuth, requireAdmin);
app.get('/api/admin/analytics', (req, res) => {
  const counts = db.prepare('SELECT event_type, COUNT(*) AS count FROM analytics_events WHERE created_at >= datetime(\'now\', \'-30 days\') GROUP BY event_type').all();
  const byType = Object.fromEntries(counts.map(row => [row.event_type, row.count]));
  const users = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  const fights = db.prepare('SELECT COUNT(*) AS count FROM fights').get().count;
  res.json({ period: '30 derniers jours', pageViews: byType.page_view || 0, signupClicks: byType.signup_cta || 0, accounts: users, fights });
});
app.get('/api/admin/users/:id', (req, res) => {
  const user = getUser.get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Aucun compte trouvé pour cet ID.' });
  res.json({ user: publicUser(user) });
});

app.patch('/api/admin/users/:id/role', requireCsrf, (req, res) => {
  const role = req.body.role;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Rôle invalide.' });
  if (req.params.id === req.user.id && role !== 'admin') return res.status(400).json({ error: 'Tu ne peux pas retirer tes propres droits admin.' });
  const target = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Aucun compte trouvé pour cet ID.' });
  if (role === 'admin' && adminEmails.has(target.email) && !getUserByEmail.get(target.email).email_verified) {
    return res.status(400).json({ error: 'Cette adresse bootstrap doit être vérifiée par e-mail avant l’activation admin.' });
  }
  if (role === 'user' && adminEmails.has(target.email)) return res.status(400).json({ error: 'Cet admin est défini dans la configuration du serveur.' });
  if (role === 'user' && target.role === 'admin' && db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").get().count <= 1) {
    return res.status(409).json({ error: 'Impossible de retirer le dernier rôle administrateur.' });
  }
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  res.json({ user: publicUser(getUser.get(req.params.id)) });
});

app.post('/api/admin/users/:id/credit', requireCsrf, (req, res) => {
  const enteredAmount = Number(req.body.amount);
  const currency = String(req.body.currency || 'USDT').toUpperCase();
  const creditRates = { USDT: 1, BTC: 65000, ETH: 3500, LTC: 80, XRP: 0.5, SOL: 150 };
  if (!Object.prototype.hasOwnProperty.call(creditRates, currency)) return res.status(400).json({ error: 'Cryptomonnaie invalide.' });
  const amount = enteredAmount * creditRates[currency];
  if (!Number.isFinite(enteredAmount) || enteredAmount <= 0 || !Number.isFinite(amount) || amount > 1000000) return res.status(400).json({ error: 'Le crédit converti doit être supérieur à 0 et inférieur à 1 000 000 USDT.' });
  const target = getUser.get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Aucun compte trouvé pour cet ID.' });
  const credit = db.transaction(() => {
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, target.id);
    db.prepare('INSERT INTO balance_credits (id, target_user_id, admin_user_id, amount, currency, entered_amount) VALUES (?, ?, ?, ?, ?, ?)').run(crypto.randomUUID(), target.id, req.user.id, amount, currency, enteredAmount);
  });
  credit();
  res.json({ user: publicUser(getUser.get(target.id)), credited: { amount: enteredAmount, currency, amountUsdt: amount } });
});

app.post('/api/admin/fights', requireCsrf, (req, res) => {
  const league = String(req.body.league || '').trim();
  const startTime = String(req.body.startTime || '').trim();
  const fighterA = String(req.body.fighterA || '').trim();
  const fighterB = String(req.body.fighterB || '').trim();
  if (!league || league.length > 60 || !startTime || startTime.length > 60 || fighterA.length < 2 || fighterA.length > 50 || fighterB.length < 2 || fighterB.length > 50 || fighterA.toLowerCase() === fighterB.toLowerCase()) {
    return res.status(400).json({ error: 'Vérifie les informations du combat. Les combattants doivent être différents.' });
  }
  const fight = { id: crypto.randomUUID(), s: 'combat', lg: league, t: startTime, a: fighterA, b: fighterB, live: req.body.live === true ? 1 : 0 };
  db.prepare('INSERT INTO fights (id, league, start_time, fighter_a, fighter_b, is_live, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)').run(fight.id, fight.lg, fight.t, fight.a, fight.b, fight.live, req.user.id);
  res.status(201).json({ fight });
});

app.delete('/api/admin/fights/:id', requireCsrf, (req, res) => {
  const result = db.prepare('UPDATE fights SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Combat introuvable ou déjà supprimé.' });
  res.json({ ok: true });
});

app.put('/api/admin/betting-window', requireCsrf, (req, res) => {
  const startTime = String(req.body.startTime || ''), endTime = String(req.body.endTime || '');
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime)) return res.status(400).json({ error: 'Saisis des heures valides.' });
  db.prepare('UPDATE betting_settings SET start_time = ?, end_time = ? WHERE id = 1').run(startTime, endTime);
  res.json(bettingWindow());
});
app.post('/api/admin/fights/:id/result', requireCsrf, (req, res) => {
  if (bettingWindow().isOpen) return res.status(400).json({ error: 'Les résultats peuvent être saisis après la fermeture des paris.' });
  const winner = Number(req.body.winner);
  if (![0, 1].includes(winner)) return res.status(400).json({ error: 'Choisis le combattant vainqueur.' });
  const fight = db.prepare('SELECT id, result_winner FROM fights WHERE id = ? AND deleted_at IS NULL').get(req.params.id);
  if (!fight) return res.status(404).json({ error: 'Combat introuvable.' });
  if (fight.result_winner !== null) return res.status(409).json({ error: 'Le résultat de ce combat est déjà enregistré.' });
  const settle = db.transaction(() => {
    const winners = db.prepare("SELECT user_id, SUM(amount * 2) AS payout FROM bet_picks WHERE fight_id = ? AND selection = ? AND status = 'pending' GROUP BY user_id").all(req.params.id, winner);
    db.prepare('UPDATE fights SET result_winner = ? WHERE id = ?').run(winner, req.params.id);
    db.prepare("UPDATE bet_picks SET status = CASE WHEN selection = ? THEN 'won' ELSE 'lost' END WHERE fight_id = ? AND status = 'pending'").run(winner, req.params.id);
    const credit = db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?');
    for (const row of winners) credit.run(row.payout, row.user_id);
    return winners.length;
  });
  const paidUsers = settle();
  res.json({ ok: true, winner, paidUsers });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'Route API introuvable.' }));
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return res.status(404).sendFile(path.join(__dirname, '404.html'));
  next();
});
app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) return res.status(400).json({ error: 'Image trop lourde ou fichier invalide (2 Mo maximum).' });
  if (error.code === 'ENOENT') return res.status(404).json({ error: 'Fichier introuvable.' });
  if (Number.isInteger(error.statusCode) && error.statusCode >= 400 && error.statusCode < 600) return res.status(error.statusCode).json({ error: error.message });
  console.error(error);
  res.status(500).json({ error: 'Erreur interne du serveur.' });
});

app.listen(port, () => console.log(`StreetFight Bet disponible sur http://localhost:${port}`));
