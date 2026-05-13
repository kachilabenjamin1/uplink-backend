/**
 * Uplink Net Pro — Backend Server
 * Handles: M-Pesa OAuth, STK Push, STK Query, Payment Callbacks
 * Deploy free on: Render · Railway · Vercel · Glitch
 */

const express  = require('express');
const cors     = require('cors');
const axios    = require('axios');
const crypto   = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── In-memory payment store (persists while server is running)
// In production swap this for a database (SQLite, Supabase, etc.)
const payments = {};   // { checkoutId: { status, receipt, phone, amount, ts } }

// ── CORS — allow your Netlify/GitHub Pages URL + localhost ──
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (Termux, Postman, same-host)
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0) return cb(null, true); // dev: allow all
    if (allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS blocked: ' + origin));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// ── Helpers ──────────────────────────────────────────────────────────

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

// Validate a Kenyan phone number → 254XXXXXXXXX
function formatPhone(raw) {
  let p = String(raw).replace(/[\s\-\(\)+]/g, '');
  if (p.startsWith('0')) p = '254' + p.slice(1);
  if (!/^254[17]\d{8}$/.test(p)) throw new Error('Invalid Kenyan phone number');
  return p;
}

// Pull M-Pesa credentials — prefer env vars, fall back to request body
// SECURITY: env vars are the safe path; body keys only for standalone/testing
function getCreds(body) {
  return {
    consumerKey:    process.env.MPESA_CONSUMER_KEY    || body.consumerKey,
    consumerSecret: process.env.MPESA_CONSUMER_SECRET || body.consumerSecret,
    shortcode:      process.env.MPESA_SHORTCODE        || body.shortcode,
    passkey:        process.env.MPESA_PASSKEY          || body.passkey,
    callbackUrl:    process.env.MPESA_CALLBACK_URL     || body.callbackUrl,
    environment:    process.env.MPESA_ENV              || body.env || 'sandbox'
  };
}

// ── ROUTES ───────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'Uplink Net Pro Backend', ts: new Date().toISOString() });
});

// ── 1. OAuth Token ────────────────────────────────────────────────────
// POST /api/mpesa/oauth/token
// Body: { env?, consumerKey?, consumerSecret? }
app.post('/api/mpesa/oauth/token', async (req, res) => {
  try {
    const { consumerKey, consumerSecret, environment } = getCreds(req.body);
    if (!consumerKey || !consumerSecret) {
      return res.status(400).json({ error: 'consumerKey and consumerSecret required' });
    }
    const credentials = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
    const base = darajaBase(environment);
    const response = await axios.get(`${base}/oauth/v1/generate?grant_type=client_credentials`, {
      headers: { Authorization: `Basic ${credentials}` },
      timeout: 10000
    });
    // Return token to the portal — never log it
    res.json({ access_token: response.data.access_token, expires_in: response.data.expires_in });
  } catch (err) {
    const msg = err.response?.data?.errorMessage || err.message;
    console.error('[OAuth] Error:', msg);
    res.status(502).json({ error: 'OAuth failed', detail: msg });
  }
});

// ── 2. STK Push ───────────────────────────────────────────────────────
// POST /api/mpesa/stkpush
// Body: { phone, amount, accountRef?, token? }
app.post('/api/mpesa/stkpush', async (req, res) => {
  try {
    const { phone: rawPhone, amount, accountRef, token: clientToken } = req.body;
    const creds = getCreds(req.body);

    if (!rawPhone || !amount) {
      return res.status(400).json({ error: 'phone and amount are required' });
    }

    const phone  = formatPhone(rawPhone);
    const base   = darajaBase(creds.environment);
    const ts     = getTimestamp();
    const password = Buffer.from(`${creds.shortcode}${creds.passkey}${ts}`).toString('base64');

    // Get a fresh token if client didn't supply one
    let bearerToken = clientToken;
    if (!bearerToken) {
      const credentials = Buffer.from(`${creds.consumerKey}:${creds.consumerSecret}`).toString('base64');
      const tokenRes = await axios.get(`${base}/oauth/v1/generate?grant_type=client_credentials`, {
        headers: { Authorization: `Basic ${credentials}` }, timeout: 10000
      });
      bearerToken = tokenRes.data.access_token;
    }

    const payload = {
      BusinessShortCode: creds.shortcode,
      Password:          password,
      Timestamp:         ts,
      TransactionType:   'CustomerPayBillOnline',
      Amount:            Math.ceil(Number(amount)),
      PartyA:            phone,
      PartyB:            creds.shortcode,
      PhoneNumber:       phone,
      CallBackURL:       creds.callbackUrl,
      AccountReference:  accountRef || 'WiFi',
      TransactionDesc:   'WiFi Bundle'
    };

    const pushRes = await axios.post(`${base}/mpesa/stkpush/v1/processrequest`, payload, {
      headers: { Authorization: `Bearer ${bearerToken}`, 'Content-Type': 'application/json' },
      timeout: 15000
    });

    const data = pushRes.data;
    if (data.ResponseCode !== '0') {
      return res.status(400).json({ error: data.CustomerMessage || 'STK Push failed', raw: data });
    }

    // Store pending payment
    payments[data.CheckoutRequestID] = {
      status:      'pending',
      phone,
      amount:      Math.ceil(Number(amount)),
      accountRef:  accountRef || 'WiFi',
      merchantId:  data.MerchantRequestID,
      checkoutId:  data.CheckoutRequestID,
      ts:          Date.now()
    };

    console.log(`[STK] Sent to ${phone} KES ${amount} — CheckoutID: ${data.CheckoutRequestID}`);
    res.json({
      ResponseCode:      data.ResponseCode,
      MerchantRequestID: data.MerchantRequestID,
      CheckoutRequestID: data.CheckoutRequestID,
      CustomerMessage:   data.CustomerMessage
    });

  } catch (err) {
    const msg = err.response?.data?.errorMessage || err.message;
    console.error('[STK Push] Error:', msg);
    res.status(502).json({ error: 'STK Push failed', detail: msg });
  }
});

// ── 3. STK Query (poll payment status) ────────────────────────────────
// POST /api/mpesa/stkquery
// Body: { checkoutId, token? }
app.post('/api/mpesa/stkquery', async (req, res) => {
  try {
    const { checkoutId, token: clientToken } = req.body;
    const creds = getCreds(req.body);

    if (!checkoutId) {
      return res.status(400).json({ error: 'checkoutId required' });
    }

    // 1. Check local store first (set by callback — fastest path)
    const local = payments[checkoutId];
    if (local && local.status === 'complete') {
      return res.json({
        ResultCode:          '0',
        ResultDesc:          'The service request is processed successfully.',
        MpesaReceiptNumber:  local.receipt,
        Amount:              local.amount,
        PhoneNumber:         local.phone
      });
    }
    if (local && local.status === 'failed') {
      return res.json({ ResultCode: local.resultCode || '1', ResultDesc: local.resultDesc || 'Payment failed' });
    }

    // 2. Query Daraja directly
    const base   = darajaBase(creds.environment);
    const ts     = getTimestamp();
    const password = Buffer.from(`${creds.shortcode}${creds.passkey}${ts}`).toString('base64');

    let bearerToken = clientToken;
    if (!bearerToken) {
      const credentials = Buffer.from(`${creds.consumerKey}:${creds.consumerSecret}`).toString('base64');
      const tokenRes = await axios.get(`${base}/oauth/v1/generate?grant_type=client_credentials`, {
        headers: { Authorization: `Basic ${credentials}` }, timeout: 10000
      });
      bearerToken = tokenRes.data.access_token;
    }

    const queryRes = await axios.post(`${base}/mpesa/stkpushquery/v1/query`, {
      BusinessShortCode: creds.shortcode,
      Password:          password,
      Timestamp:         ts,
      CheckoutRequestID: checkoutId
    }, {
      headers: { Authorization: `Bearer ${bearerToken}`, 'Content-Type': 'application/json' },
      timeout: 10000
    });

    res.json(queryRes.data);

  } catch (err) {
    const msg = err.response?.data?.errorMessage || err.message;
    console.error('[Query] Error:', msg);
    // Return a "still processing" response so the portal keeps polling
    res.json({ ResultCode: '', ResultDesc: 'Processing', detail: msg });
  }
});

// ── 4. M-Pesa Callback (Safaricom calls this after payment) ───────────
// POST /api/mpesa/callback
// No auth — Safaricom doesn't send auth headers
app.post('/api/mpesa/callback', (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) {
      console.warn('[Callback] Malformed body:', JSON.stringify(req.body));
      return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
    }

    const { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } = body;
    console.log(`[Callback] CheckoutID: ${CheckoutRequestID} — ResultCode: ${ResultCode} — ${ResultDesc}`);

    if (String(ResultCode) === '0') {
      // Payment successful — extract metadata
      const meta = {};
      (CallbackMetadata?.Item || []).forEach(item => { if (item.Name) meta[item.Name] = item.Value; });

      const receipt = meta.MpesaReceiptNumber;
      const amount  = meta.Amount;
      const phone   = meta.PhoneNumber;

      payments[CheckoutRequestID] = {
        status:  'complete',
        receipt,
        amount,
        phone,
        merchantId: MerchantRequestID,
        ts: Date.now()
      };

      console.log(`[Callback] ✅ Payment confirmed — Receipt: ${receipt} | KES ${amount} | ${phone}`);

    } else {
      // Payment failed or cancelled
      if (payments[CheckoutRequestID]) {
        payments[CheckoutRequestID].status     = 'failed';
        payments[CheckoutRequestID].resultCode = String(ResultCode);
        payments[CheckoutRequestID].resultDesc = ResultDesc;
      } else {
        payments[CheckoutRequestID] = {
          status: 'failed', resultCode: String(ResultCode), resultDesc: ResultDesc, ts: Date.now()
        };
      }
      console.log(`[Callback] ❌ Payment failed — ${ResultDesc}`);
    }

    // Always respond 200 to Safaricom immediately
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

  } catch (err) {
    console.error('[Callback] Error processing:', err.message);
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' }); // still 200 — don't let Safaricom retry loop
  }
});

// ── 5. Payment status check (portal polls this after callback) ─────────
// GET /api/payment/status/:checkoutId
app.get('/api/payment/status/:checkoutId', (req, res) => {
  const p = payments[req.params.checkoutId];
  if (!p) return res.json({ status: 'pending' });
  res.json(p);
});

// ── 6. List recent payments (admin dashboard) ─────────────────────────
// GET /api/payments — only works from same origin or with admin key
app.get('/api/payments', (req, res) => {
  const adminKey = process.env.ADMIN_SECRET;
  if (adminKey && req.headers['x-admin-key'] !== adminKey) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const list = Object.values(payments)
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 100); // last 100
  res.json(list);
});

// ── Clean up old pending payments (older than 15 min) every 10 min ────
setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  let cleaned = 0;
  for (const [id, p] of Object.entries(payments)) {
    if (p.ts < cutoff && p.status === 'pending') { delete payments[id]; cleaned++; }
  }
  if (cleaned > 0) console.log(`[Cleanup] Removed ${cleaned} stale pending payments`);
}, 10 * 60 * 1000);

// ── Start ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Uplink Net Pro backend running on port ${PORT}`);
  console.log(`   Health:   http://localhost:${PORT}/`);
  console.log(`   Callback: http://localhost:${PORT}/api/mpesa/callback`);
  console.log(`   Mode:     ${process.env.MPESA_ENV || 'sandbox'}\n`);
});
