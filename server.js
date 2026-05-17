/**
 * Uplink Net Pro — Secure Backend Server v2.0
 * ─────────────────────────────────────────────
 * Security features:
 *  ✓ Rate limiting (global + per-route)
 *  ✓ Brute force protection on auth/payment endpoints
 *  ✓ Helmet (14 HTTP security headers)
 *  ✓ Input validation & sanitization on every route
 *  ✓ Request size limits (prevents payload flooding)
 *  ✓ IP-based lockout after repeated failures
 *  ✓ Suspicious request detection & logging
 *  ✓ Callback payload structure validation
 *  ✓ CORS strict allowlist
 *  ✓ Admin key protection on sensitive routes
 *  ✓ Timing-safe secret comparison
 *  ✓ No sensitive data in logs or responses
 */

const express      = require('express');
const cors         = require('cors');
const axios        = require('axios');
const crypto       = require('crypto');
const rateLimit    = require('express-rate-limit');
const slowDown     = require('express-slow-down');
const helmet       = require('helmet');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════════════════════════════════
//  IN-MEMORY STORES
// ════════════════════════════════════════════════════════════════════
const payments   = {};  // checkoutId → payment record
const failedIPs  = {};  // ip → { count, lockedUntil }
const requestLog = [];  // ring buffer — last 1000 requests

// ════════════════════════════════════════════════════════════════════
//  SECURITY CONSTANTS
// ════════════════════════════════════════════════════════════════════
const MAX_FAIL_ATTEMPTS = parseInt(process.env.MAX_FAIL_ATTEMPTS || '5');
const LOCKOUT_MINUTES   = parseInt(process.env.LOCKOUT_MINUTES   || '15');
const LOCKOUT_MS        = LOCKOUT_MINUTES * 60 * 1000;

// ════════════════════════════════════════════════════════════════════
//  HELMET — 14 HTTP security headers
// ════════════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      objectSrc:  ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts:        { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard:  { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' }
}));

// ════════════════════════════════════════════════════════════════════
//  CORS — strict allowlist
// ════════════════════════════════════════════════════════════════════
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin)                          return cb(null, true); // same-host / Termux
    if (allowedOrigins.length === 0)      return cb(null, true); // dev: allow all
    if (allowedOrigins.includes(origin))  return cb(null, true);
    logSuspicious(null, 'CORS blocked from: ' + origin);
    cb(new Error('CORS policy: origin not allowed'));
  },
  methods:        ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
  credentials:    false
}));

// ════════════════════════════════════════════════════════════════════
//  REQUEST SIZE LIMITS
// ════════════════════════════════════════════════════════════════════
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ════════════════════════════════════════════════════════════════════
//  RATE LIMITERS
// ════════════════════════════════════════════════════════════════════

// Global — 120 req / 1 min per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, max: 120,
  standardHeaders: true, legacyHeaders: false,
  handler: (req, res, next, opts) => {
    logSuspicious(req, 'Global rate limit hit');
    res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  }
});
app.use(globalLimiter);

// STK Push — 5 req / 5 min per IP  (prevents flooding M-Pesa, costs real money)
const stkLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 5,
  handler: (req, res, next, opts) => {
    logSuspicious(req, 'STK Push rate limit hit');
    res.status(429).json({ error: 'Too many payment requests. Wait 5 minutes.' });
  }
});

// STK slow-down — add 500ms delay after 3 pushes in 5 min
const stkSlowDown = slowDown({
  windowMs: 5 * 60 * 1000, delayAfter: 3, delayMs: () => 500
});

// OAuth — 20 req / 10 min per IP
const oauthLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 20,
  message: { error: 'Too many token requests.' }
});

// Query / status polling — 60 req / min per IP
const queryLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  message: { error: 'Polling too fast.' }
});

// Admin routes — 30 req / 10 min per IP
const adminLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 30,
  message: { error: 'Too many admin requests.' }
});

// ════════════════════════════════════════════════════════════════════
//  IP LOCKOUT  (applied to payment-sensitive routes)
// ════════════════════════════════════════════════════════════════════
function ipLockout(req, res, next) {
  const ip  = getIP(req);
  const rec = failedIPs[ip];
  if (rec && rec.lockedUntil && Date.now() < rec.lockedUntil) {
    const mins = Math.ceil((rec.lockedUntil - Date.now()) / 60000);
    logSuspicious(req, `Locked IP attempted access — ${mins}m remaining`);
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${mins} minute(s).`
    });
  }
  next();
}

function recordFailure(req) {
  const ip = getIP(req);
  if (!failedIPs[ip]) failedIPs[ip] = { count: 0, lockedUntil: null };
  failedIPs[ip].count++;
  if (failedIPs[ip].count >= MAX_FAIL_ATTEMPTS) {
    failedIPs[ip].lockedUntil = Date.now() + LOCKOUT_MS;
    logSuspicious(req, `IP locked out after ${MAX_FAIL_ATTEMPTS} failures`);
  }
}

function clearFailure(ip) { delete failedIPs[ip]; }

// ════════════════════════════════════════════════════════════════════
//  REQUEST LOGGING MIDDLEWARE
// ════════════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  requestLog.push({
    ts:     new Date().toISOString(),
    ip:     getIP(req),
    method: req.method,
    path:   req.path,
    ua:     (req.headers['user-agent'] || '—').slice(0, 80)
  });
  if (requestLog.length > 1000) requestLog.shift();
  next();
});

// ════════════════════════════════════════════════════════════════════
//  ADMIN KEY MIDDLEWARE
// ════════════════════════════════════════════════════════════════════
function requireAdmin(req, res, next) {
  const adminKey = process.env.ADMIN_SECRET;
  if (!adminKey) return next(); // not configured → dev mode
  const supplied = req.headers['x-admin-key'] || req.query.key || '';
  if (!timingSafeEqual(String(supplied), adminKey)) {
    logSuspicious(req, 'Bad admin key');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ════════════════════════════════════════════════════════════════════
//  INPUT VALIDATION
// ════════════════════════════════════════════════════════════════════
const PHONE_RE    = /^254[17]\d{8}$/;
const CHECKOUT_RE = /^[a-zA-Z0-9_\-]{10,60}$/;
const REF_RE      = /^[a-zA-Z0-9 _\-]{1,20}$/;
const KEY_RE      = /^[a-zA-Z0-9+/=]{20,200}$/;
const AMOUNT_MIN  = 1;
const AMOUNT_MAX  = 150000;

function validate(schema, data) {
  const errors = [];
  for (const [field, rule] of Object.entries(schema)) {
    const val = data[field];
    const missing = val === undefined || val === null || val === '';
    if (rule.required && missing) { errors.push(`${field} is required`); continue; }
    if (missing) continue;
    if (rule.type === 'number') {
      const n = Number(val);
      if (isNaN(n))              errors.push(`${field} must be a number`);
      else if (n < rule.min)     errors.push(`${field} min is ${rule.min}`);
      else if (n > rule.max)     errors.push(`${field} max is ${rule.max}`);
    }
    if (rule.pattern && !rule.pattern.test(String(val))) {
      errors.push(`${field}: invalid format`);
    }
    if (rule.maxLen && String(val).length > rule.maxLen) {
      errors.push(`${field} too long (max ${rule.maxLen})`);
    }
  }
  return errors;
}

// ════════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════════
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

function darajaBase(env) {
  return env === 'live'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';
}

function getTimestamp() {
  const d = new Date();
  return [
    d.getFullYear(),
    String(d.getMonth() + 1).padStart(2, '0'),
    String(d.getDate()).padStart(2, '0'),
    String(d.getHours()).padStart(2, '0'),
    String(d.getMinutes()).padStart(2, '0'),
    String(d.getSeconds()).padStart(2, '0')
  ].join('');
}

function formatPhone(raw) {
  let p = String(raw).replace(/[\s\-\(\)+]/g, '');
  if (p.startsWith('0')) p = '254' + p.slice(1);
  if (!PHONE_RE.test(p)) throw new Error('Invalid Kenyan phone number');
  return p;
}

// Timing-safe comparison — prevents timing attacks on secrets
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // Always run the comparison regardless of length mismatch
  const bA = Buffer.from(a.padEnd(Math.max(a.length, b.length), '\0'));
  const bB = Buffer.from(b.padEnd(Math.max(a.length, b.length), '\0'));
  return crypto.timingSafeEqual(bA, bB) && a.length === b.length;
}

// Credentials — env vars are authoritative; body only in dev mode
function getCreds(body) {
  return {
    consumerKey:    process.env.MPESA_CONSUMER_KEY    || body?.consumerKey    || '',
    consumerSecret: process.env.MPESA_CONSUMER_SECRET || body?.consumerSecret || '',
    shortcode:      process.env.MPESA_SHORTCODE        || body?.shortcode      || '',
    passkey:        process.env.MPESA_PASSKEY          || body?.passkey        || '',
    callbackUrl:    process.env.MPESA_CALLBACK_URL     || body?.callbackUrl    || '',
    environment:    process.env.MPESA_ENV              || body?.env            || 'sandbox'
  };
}

function logSuspicious(req, reason) {
  const ip = req ? getIP(req) : '?';
  console.warn(`[SECURITY] ${new Date().toISOString()} | IP: ${ip} | ${reason}`);
}

async function getToken(creds) {
  const base = darajaBase(creds.environment);
  const credentials = Buffer.from(`${creds.consumerKey}:${creds.consumerSecret}`).toString('base64');
  const r = await axios.get(
    `${base}/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${credentials}` }, timeout: 10000 }
  );
  if (!r.data.access_token) throw new Error('No access token returned');
  return r.data.access_token;
}

// ════════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════════

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Uplink Net Pro Backend', version: '2.0.0', ts: new Date().toISOString() });
});

// ── 1. OAuth Token ────────────────────────────────────────────────────
app.post('/api/mpesa/oauth/token', oauthLimiter, ipLockout, async (req, res) => {
  const creds = getCreds(req.body);
  if (!creds.consumerKey || !creds.consumerSecret) {
    recordFailure(req);
    return res.status(400).json({ error: 'M-Pesa credentials not configured on server' });
  }
  if (!KEY_RE.test(creds.consumerKey) || !KEY_RE.test(creds.consumerSecret)) {
    recordFailure(req);
    logSuspicious(req, 'Malformed credential format in OAuth request');
    return res.status(400).json({ error: 'Invalid credential format' });
  }
  try {
    const token = await getToken(creds);
    clearFailure(getIP(req));
    res.json({ access_token: token }); // never echo credentials back
  } catch (err) {
    recordFailure(req);
    console.error(`[OAuth] ${err.response?.data?.errorMessage || err.message}`);
    res.status(502).json({ error: 'OAuth failed — check credentials in server config' });
  }
});

// ── 2. STK Push ───────────────────────────────────────────────────────
app.post('/api/mpesa/stkpush', stkLimiter, stkSlowDown, ipLockout, async (req, res) => {
  // Validate inputs
  const errors = validate({
    phone:  { required: true },
    amount: { required: true, type: 'number', min: AMOUNT_MIN, max: AMOUNT_MAX }
  }, req.body);
  if (errors.length) return res.status(400).json({ error: 'Validation failed', details: errors });

  const creds = getCreds(req.body);
  if (!creds.shortcode || !creds.passkey || !creds.consumerKey) {
    return res.status(500).json({ error: 'M-Pesa not fully configured on server' });
  }

  let phone;
  try { phone = formatPhone(req.body.phone); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  const amount     = Math.ceil(Number(req.body.amount));
  const accountRef = String(req.body.accountRef || 'WiFi')
    .replace(/[^a-zA-Z0-9 _-]/g, '').slice(0, 20) || 'WiFi';

  try {
    const base     = darajaBase(creds.environment);
    const ts       = getTimestamp();
    const password = Buffer.from(`${creds.shortcode}${creds.passkey}${ts}`).toString('base64');
    const token    = await getToken(creds);

    const pushRes = await axios.post(
      `${base}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: creds.shortcode,
        Password:          password,
        Timestamp:         ts,
        TransactionType:   'CustomerPayBillOnline',
        Amount:            amount,
        PartyA:            phone,
        PartyB:            creds.shortcode,
        PhoneNumber:       phone,
        CallBackURL:       creds.callbackUrl,
        AccountReference:  accountRef,
        TransactionDesc:   'WiFi Bundle'
      },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 15000 }
    );

    const data = pushRes.data;
    if (data.ResponseCode !== '0') {
      recordFailure(req);
      return res.status(400).json({ error: data.CustomerMessage || 'STK Push rejected', code: data.ResponseCode });
    }

    // Store pending — keep full phone server-side only, mask in record
    payments[data.CheckoutRequestID] = {
      status:     'pending',
      phone:      phone.slice(0, 7) + '••••', // masked
      phoneFull:  phone,                        // server-side only
      amount,
      accountRef,
      merchantId: data.MerchantRequestID,
      checkoutId: data.CheckoutRequestID,
      ts:         Date.now()
    };

    clearFailure(getIP(req));
    console.log(`[STK] Sent | KES ${amount} | ${phone.slice(0, 7)}•••• | ${data.CheckoutRequestID}`);

    res.json({
      ResponseCode:      data.ResponseCode,
      MerchantRequestID: data.MerchantRequestID,
      CheckoutRequestID: data.CheckoutRequestID,
      CustomerMessage:   data.CustomerMessage
    });

  } catch (err) {
    recordFailure(req);
    console.error('[STK]', err.response?.data?.errorMessage || err.message);
    res.status(502).json({ error: 'STK Push failed — please try again' });
  }
});

// ── 3. STK Query ──────────────────────────────────────────────────────
app.post('/api/mpesa/stkquery', queryLimiter, async (req, res) => {
  const { checkoutId } = req.body;
  if (!checkoutId || !CHECKOUT_RE.test(checkoutId)) {
    return res.status(400).json({ error: 'Invalid checkoutId format' });
  }

  // Check local store first (set by callback — fastest path, no Daraja call)
  const local = payments[checkoutId];
  if (local?.status === 'complete') {
    return res.json({ ResultCode: '0', ResultDesc: 'Processed successfully.',
      MpesaReceiptNumber: local.receipt, Amount: local.amount });
  }
  if (local?.status === 'failed') {
    return res.json({ ResultCode: local.resultCode || '1', ResultDesc: local.resultDesc || 'Payment failed' });
  }

  // Query Daraja
  const creds = getCreds(req.body);
  try {
    const base     = darajaBase(creds.environment);
    const ts       = getTimestamp();
    const password = Buffer.from(`${creds.shortcode}${creds.passkey}${ts}`).toString('base64');
    const token    = await getToken(creds);
    const r = await axios.post(
      `${base}/mpesa/stkpushquery/v1/query`,
      { BusinessShortCode: creds.shortcode, Password: password, Timestamp: ts, CheckoutRequestID: checkoutId },
      { headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 10000 }
    );
    res.json(r.data);
  } catch (err) {
    res.json({ ResultCode: '', ResultDesc: 'Processing' }); // blip — keep polling
  }
});

// ── 4. M-Pesa Callback  (Safaricom → this server) ─────────────────────
app.post('/api/mpesa/callback', (req, res) => {
  // Always 200 immediately — Safaricom retries on slow responses
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  try {
    // Reject oversized payloads
    if (JSON.stringify(req.body).length > 5000) {
      logSuspicious(req, 'Oversized callback payload — ignoring'); return;
    }

    const cb = req.body?.Body?.stkCallback;
    if (!cb || typeof cb.CheckoutRequestID !== 'string') {
      console.warn('[Callback] Malformed body — ignoring'); return;
    }
    if (!CHECKOUT_RE.test(cb.CheckoutRequestID)) {
      logSuspicious(req, 'Invalid CheckoutRequestID in callback'); return;
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = cb;

    if (String(ResultCode) === '0') {
      const meta = {};
      (CallbackMetadata?.Item || []).forEach(i => { if (i?.Name) meta[i.Name] = i.Value; });
      const receipt = String(meta.MpesaReceiptNumber || '').replace(/[^A-Z0-9]/g, '');
      const amount  = Number(meta.Amount) || 0;
      payments[CheckoutRequestID] = {
        ...(payments[CheckoutRequestID] || {}),
        status: 'complete', receipt, amount, confirmedAt: Date.now()
      };
      console.log(`[Callback] ✅ Receipt: ${receipt} | KES ${amount}`);
    } else {
      payments[CheckoutRequestID] = {
        ...(payments[CheckoutRequestID] || {}),
        status: 'failed',
        resultCode: String(ResultCode),
        resultDesc: String(ResultDesc).slice(0, 100),
        failedAt: Date.now()
      };
      console.log(`[Callback] ❌ Code ${ResultCode}: ${ResultDesc}`);
    }
  } catch (err) {
    console.error('[Callback] Processing error:', err.message);
  }
});

// ── 5. Payment status (portal polls this) ─────────────────────────────
app.get('/api/payment/status/:checkoutId', queryLimiter, (req, res) => {
  const { checkoutId } = req.params;
  if (!CHECKOUT_RE.test(checkoutId)) {
    return res.status(400).json({ error: 'Invalid checkoutId' });
  }
  const p = payments[checkoutId];
  if (!p) return res.json({ status: 'pending' });
  const { phoneFull, ...safe } = p; // never return full phone
  res.json(safe);
});

// ── 6. List payments (admin only) ─────────────────────────────────────
app.get('/api/payments', adminLimiter, requireAdmin, (req, res) => {
  const list = Object.values(payments)
    .map(({ phoneFull, ...safe }) => safe)
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 100);
  res.json({ count: list.length, payments: list });
});

// ── 7. Request log (admin only) ───────────────────────────────────────
app.get('/api/logs', adminLimiter, requireAdmin, (req, res) => {
  res.json({ count: requestLog.length, logs: [...requestLog].reverse().slice(0, 200) });
});

// ── 8. Locked IPs (admin only) ────────────────────────────────────────
app.get('/api/security/locked', adminLimiter, requireAdmin, (req, res) => {
  const now    = Date.now();
  const locked = Object.entries(failedIPs)
    .filter(([, r]) => r.lockedUntil && now < r.lockedUntil)
    .map(([ip, r]) => ({ ip, attempts: r.count, unlocksAt: new Date(r.lockedUntil).toISOString() }));
  res.json({ locked });
});

// ── 9. Unlock IP (admin only) ─────────────────────────────────────────
app.post('/api/security/unlock', adminLimiter, requireAdmin, (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  if (!ip) return res.status(400).json({ error: 'ip required' });
  delete failedIPs[ip];
  console.log(`[Admin] Unlocked IP: ${ip}`);
  res.json({ ok: true, message: `${ip} unlocked` });
});

// ════════════════════════════════════════════════════════════════════
//  CATCH-ALL — block route probing
// ════════════════════════════════════════════════════════════════════
app.use((req, res) => {
  logSuspicious(req, `404 probe: ${req.method} ${req.path}`);
  res.status(404).json({ error: 'Not found' });
});

// Global error handler — never leak stack traces
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ════════════════════════════════════════════════════════════════════
//  MAINTENANCE — runs every 10 min
// ════════════════════════════════════════════════════════════════════
setInterval(() => {
  const now       = Date.now();
  const pCutoff   = now - 15 * 60 * 1000;  // drop stale pending payments after 15m
  const ipCutoff  = now - 60 * 60 * 1000;  // drop lockout records after 1h
  let pc = 0, ic = 0;
  for (const [id, p] of Object.entries(payments)) {
    if (p.ts < pCutoff && p.status === 'pending') { delete payments[id]; pc++; }
  }
  for (const [ip, r] of Object.entries(failedIPs)) {
    if (!r.lockedUntil || r.lockedUntil < ipCutoff) { delete failedIPs[ip]; ic++; }
  }
  if (pc || ic) console.log(`[Cleanup] ${pc} stale payments, ${ic} old lockout records removed`);
}, 10 * 60 * 1000);

// ════════════════════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n🚀 Uplink Net Pro Backend v2.0 — port ${PORT}`);
  console.log(`   Mode:       ${process.env.MPESA_ENV || 'sandbox'}`);
  console.log(`   Limits:     120 req/min global | 5 STK/5min | 20 OAuth/10min`);
  console.log(`   IP lockout: ${MAX_FAIL_ATTEMPTS} failures → ${LOCKOUT_MINUTES}min lock`);
  console.log(`   CORS:       ${allowedOrigins.length ? allowedOrigins.join(', ') : 'ALL (dev mode)'}`);
  console.log(`   Admin key:  ${process.env.ADMIN_SECRET ? '✓ configured' : '⚠ not set (open)'}\n`);
});
