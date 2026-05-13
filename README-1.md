# Uplink Net Pro — Backend Deployment Guide

## What this server does

| Endpoint | Purpose |
|---|---|
| `POST /api/mpesa/oauth/token` | Gets Daraja access token (avoids CORS in browser) |
| `POST /api/mpesa/stkpush` | Sends STK Push to customer's phone |
| `POST /api/mpesa/stkquery` | Checks if customer paid |
| `POST /api/mpesa/callback` | Safaricom calls this when payment completes |
| `GET /api/payment/status/:id` | Portal polls this to confirm payment |
| `GET /api/payments` | Admin view of recent payments |

---

## Option A — Deploy on Render (free, recommended)

1. Push this folder to a GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Set:
   - **Build command:** `npm install`
   - **Start command:** `node server.js`
5. Add environment variables (from .env.example) in the Render dashboard
6. Deploy — you get a URL like `https://uplink-backend.onrender.com`

---

## Option B — Deploy on Railway (free tier)

1. Go to https://railway.app → New Project → Deploy from GitHub
2. Connect your repo
3. Add environment variables in the Variables tab
4. Railway auto-detects Node.js and deploys

---

## Option C — Run on your Android phone with Termux

```bash
# Install Termux from F-Droid, then:
pkg update && pkg install nodejs git

# Clone or copy your backend files
mkdir uplink-backend && cd uplink-backend

# Copy server.js, package.json, .env.example into this folder
# Then:
cp .env.example .env
nano .env   # fill in your credentials

npm install
node server.js
```

Server runs at `http://localhost:3000`
Other devices on your WiFi reach it at `http://YOUR_PHONE_IP:3000`

---

## Connecting the admin dashboard to this backend

In the admin dashboard:
1. Go to **Settings → M-Pesa Config**
2. Set **M-Pesa Proxy URL** to your backend URL:
   - Render: `https://uplink-backend.onrender.com/api/mpesa`
   - Termux: `http://192.168.x.x:3000/api/mpesa`
3. Fill in Shortcode, Passkey, Consumer Key, Consumer Secret
4. Set **Callback URL** to: `https://your-backend.onrender.com/api/mpesa/callback`
5. Click **Save & Publish**

The portals will now use your backend for all M-Pesa calls.

---

## Setting up Safaricom Daraja

### Sandbox (for testing)
1. Register at https://developer.safaricom.co.ke
2. Create an app → get Consumer Key and Consumer Secret
3. Use shortcode `174379` and the test passkey from .env.example
4. Use any test phone: `254708374149`

### Going Live
1. Apply for Go-Live in the Daraja portal
2. Replace sandbox credentials with live ones
3. Change `MPESA_ENV=live` in your environment variables
4. Update callback URL to your real HTTPS server URL
5. Safaricom requires HTTPS for callbacks — Render/Railway give you this for free

---

## How the full payment flow works

```
Customer taps "Pay" on portal
        ↓
Portal → POST /api/mpesa/stkpush → Daraja API
        ↓
Daraja sends STK prompt to customer's phone
        ↓
Customer enters PIN
        ↓
Daraja → POST /api/mpesa/callback → Your server
        ↓
Server stores payment as "complete"
        ↓
Portal polls GET /api/payment/status/:checkoutId
        ↓
Portal shows success screen + receipt number
```

---

## Security notes

- Your M-Pesa keys live in environment variables — never in code
- The `.env` file is in `.gitignore` — never committed to GitHub
- CORS is locked to your frontend origin only
- The `/api/payments` admin endpoint requires `x-admin-key` header
- The callback endpoint accepts all IPs (Safaricom IPs are not fixed)
  but validates the payload structure

---

## Testing with curl

```bash
# Test server health
curl http://localhost:3000/

# Test OAuth token (uses env var credentials)
curl -X POST http://localhost:3000/api/mpesa/oauth/token

# Test STK Push (sandbox)
curl -X POST http://localhost:3000/api/mpesa/stkpush \
  -H "Content-Type: application/json" \
  -d '{"phone":"0708374149","amount":1,"accountRef":"Test"}'

# Simulate a callback (what Safaricom sends you)
curl -X POST http://localhost:3000/api/mpesa/callback \
  -H "Content-Type: application/json" \
  -d '{
    "Body": {
      "stkCallback": {
        "MerchantRequestID": "test-merchant-id",
        "CheckoutRequestID": "ws_CO_123456",
        "ResultCode": 0,
        "ResultDesc": "The service request is processed successfully.",
        "CallbackMetadata": {
          "Item": [
            {"Name":"Amount","Value":100},
            {"Name":"MpesaReceiptNumber","Value":"QGH2X3K9A"},
            {"Name":"PhoneNumber","Value":254712345678}
          ]
        }
      }
    }
  }'
```
