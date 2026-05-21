# Uplink Net Pro — Backend v2.0

## ✅ Pre-Configured M-Pesa Sandbox Settings

Your `.env` is ready with:
- Consumer Key & Secret → configured
- Shortcode: `174379` (Safaricom sandbox)
- Passkey: sandbox passkey (configured)
- Environment: `sandbox`
- Admin Secret: configured (see `.env`)

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
cd uplink-backend-v2
npm install
```

### 2. Start the server (local test)
```bash
node server.js
```
Server starts on `http://localhost:3000`

---

## 🌐 Deploy to Render (Free)

1. Push to GitHub (make sure `.env` is in `.gitignore` ✓)
2. Go to https://render.com → New Web Service
3. Connect your repo, set runtime to **Node**
4. Add these Environment Variables in Render dashboard:

| Key | Value |
|-----|-------|
| `MPESA_CONSUMER_KEY` | `Vzx5E8QuCtAvNVGtWGq1HrPpLp334QsAOQ0pu2eMbSam4VG6` |
| `MPESA_CONSUMER_SECRET` | `eHGKG8i0SPydHEbspSicOSlUF7s3E40HOS5CO0cAZ30eUmUrdTJqRJQpnwkUGPDR` |
| `MPESA_SHORTCODE` | `174379` |
| `MPESA_PASSKEY` | `bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919` |
| `MPESA_ENV` | `sandbox` |
| `MPESA_CALLBACK_URL` | `https://YOUR-APP.onrender.com/api/mpesa/callback` |
| `ADMIN_SECRET` | `e6f33035dc6c93ee84c49fa10249aa50260bf3f8df5ac033d26f92555cad5b15` |

5. Once deployed, your backend URL is: `https://YOUR-APP.onrender.com`

---

## ⚠️ After Deploying — Update Callback URL

Once you have your Render URL, update **two places**:

**A) In `.env` (for local runs):**
```
MPESA_CALLBACK_URL=https://YOUR-APP.onrender.com/api/mpesa/callback
```

**B) In Admin Dashboard → Settings → M-Pesa API Configuration:**
- Backend Server URL: `https://YOUR-APP.onrender.com`
- Callback URL: `https://YOUR-APP.onrender.com/api/mpesa/callback`
- Click **Save & Publish Config**

---

## 🧪 Testing STK Push

1. Open the Admin Dashboard → Settings → API Config
2. Click **Test OAuth Token** — should return ✓
3. Open the Captive Portal in a browser
4. Enter a **Safaricom sandbox test phone**: `254708374149`
5. Select a package → pay → you should see the STK push request

> **Note:** In sandbox mode, STK push prompts don't actually appear on phones.
> The callback returns success automatically after a few seconds.

---

## 🔑 Your Admin Secret Key
```
e6f33035dc6c93ee84c49fa10249aa50260bf3f8df5ac033d26f92555cad5b15
```
Keep this secret. It protects `/api/payments`, `/api/logs`, and `/api/security/*`.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| POST | `/api/mpesa/oauth/token` | Get OAuth token |
| POST | `/api/mpesa/stkpush` | Trigger STK push |
| POST | `/api/mpesa/stkquery` | Query payment status |
| POST | `/api/mpesa/callback` | Safaricom callback receiver |
| GET | `/api/payment/status/:id` | Poll payment status |
| GET | `/api/payments` | List payments (admin) |
| GET | `/api/logs` | Request logs (admin) |
| GET | `/api/security/locked` | Locked IPs (admin) |
| POST | `/api/security/unlock` | Unlock IP (admin) |
