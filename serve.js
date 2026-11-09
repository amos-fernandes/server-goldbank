'use strict';
/**
 * AIBANK Server — DEMO_MODE minimal (unblocks Render)
 * Auth demo, wallet mock, pix mock, health — sem Necta/Azify
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
require('dotenv').config({ path: '.env.private' });

const {
  JWT_SECRET = 'dev-secret-CHANGE-IN-PROD',
  PORT = 8082,
  NODE_ENV = 'development',
} = process.env;

const DEMO_EMAIL = 'demo@aibank.com.br';
const DEMO_USER = {
  id: 'cus_demo_001',
  name: 'Usuário Demo',
  email: DEMO_EMAIL,
  nectaStatus: 'ACTIVE',
  nectaAccountId: 'acc_demo_001',
  walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18',
  kycStatus: 'APPROVED',
  kycDocumentId: 'doc_demo_001',
  pixKeys: [{ key: 'demo@pix.com', type: 'EMAIL' }],
  token: null,
};

const inMemoryUsers = new Map();
inMemoryUsers.set(DEMO_USER.id, DEMO_USER);

function issueToken(userId, email) {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '7d' });
}
function safeUser(user) {
  const { passwordHash, encryptedPrivateKey, mbCredentials, ...pub } = user || {};
  return pub;
}
function isDemoEmail(email) {
  return email && email.toLowerCase() === DEMO_EMAIL;
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '2mb' }));

app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Request-Timestamp, X-App-Platform, X-App-Version, x-demo-mode');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function authenticateToken(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token ausente.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.userId === DEMO_USER.id || payload.email === DEMO_EMAIL) {
      req.user = { ...DEMO_USER, token };
      return next();
    }
    const u = inMemoryUsers.get(payload.userId);
    if (!u) return res.status(401).json({ error: 'Usuário inválido.' });
    req.user = { ...u, token };
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido.' });
  }
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, mode: 'DEMO', service: 'server-goldbank', ts: new Date().toISOString() });
});
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, mode: 'DEMO', service: 'server-goldbank', ts: new Date().toISOString() });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email obrigatório.' });
  if (isDemoEmail(email)) {
    const token = issueToken(DEMO_USER.id, DEMO_USER.email);
    DEMO_USER.token = token;
    return res.json(safeUser({ ...DEMO_USER, token }));
  }
  const key = email.toLowerCase();
  let user = null;
  for (const u of inMemoryUsers.values()) {
    if (u.email === key) { user = u; break; }
  }
  if (!user) return res.status(401).json({ error: 'Conta não encontrada. Registre-se primeiro.' });
  if (user.passwordHash && password) {
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Senha incorreta.' });
  }
  const token = issueToken(user.id, user.email);
  user.token = token;
  res.json(safeUser({ ...user, token }));
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email e password são obrigatórios no modo demo.' });
  }
  const normalized = email.toLowerCase().trim();
  if (isDemoEmail(normalized)) {
    return res.status(400).json({ error: 'Use o login demo@aibank.com.br — conta já existe.' });
  }
  for (const u of inMemoryUsers.values()) {
    if (u.email === normalized) return res.status(409).json({ error: 'Email já cadastrado.' });
  }
  const id = 'cus_local_' + Date.now();
  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id,
    name,
    email: normalized,
    passwordHash,
    nectaStatus: 'ACTIVE',
    nectaAccountId: 'acc_local_' + Date.now(),
    walletAddress: '0x' + crypto.randomBytes(20).toString('hex'),
    kycStatus: 'APPROVED',
    pixKeys: [],
    token: null,
  };
  inMemoryUsers.set(id, user);
  const token = issueToken(id, normalized);
  user.token = token;
  res.status(201).json(safeUser({ ...user, token }));
});

app.post('/api/auth/demo', (_req, res) => {
  const token = issueToken(DEMO_USER.id, DEMO_USER.email);
  DEMO_USER.token = token;
  res.json(safeUser({ ...DEMO_USER, token }));
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json(safeUser(req.user));
});

app.get('/api/wallet/balance', authenticateToken, (_req, res) => {
  res.json({
    balance: 12500.5,
    availableBalance: 12500.5,
    currency: 'BRL',
    provider: 'demo',
  });
});

app.get('/api/wallet/transactions', authenticateToken, (_req, res) => {
  res.json({
    transactions: [
      { id: 'demo_1', type: 'CREDIT', description: 'Depósito PIX demo', amount: 500, createdAt: new Date().toISOString() },
      { id: 'demo_2', type: 'DEBIT', description: 'Transferência PIX demo', amount: -50, createdAt: new Date().toISOString() },
    ],
    provider: 'demo',
  });
});

app.post('/api/pix/deposit', authenticateToken, (req, res) => {
  const amount = Number(req.body?.amount || 0);
  if (!amount || amount < 1) return res.status(400).json({ error: 'Valor mínimo de R$ 1,00.' });
  const ts = Date.now();
  const val = (amount / 100).toFixed(2);
  res.json({
    success: true,
    provider: 'demo',
    paymentLink: `https://server-goldbank.onrender.com/demo/pix/${ts}`,
    qrCodeBase64: '',
    qrCodePayload: `00020101021226840014br.gov.bcb.pix0136aibank-demo-${ts}5204000053039865405${val}5802BR5915AIBANK DEMO6008SAO PAULO62070503***6304ABCD`,
    value: amount / 100,
    chargeId: `demo_charge_${ts}`,
    expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
  });
});

app.post('/api/pix/send', authenticateToken, (req, res) => {
  const amount = Number(req.body?.amount || 0);
  if (!amount || amount < 1) return res.status(400).json({ error: 'Valor inválido.' });
  res.json({
    success: true,
    provider: 'demo',
    id: `demo_tx_${Date.now()}`,
    status: 'COMPLETED',
    value: amount / 100,
  });
});

app.get('/api/user/pix-keys', authenticateToken, (req, res) => {
  res.json(req.user.pixKeys || DEMO_USER.pixKeys);
});

app.get('/api/crypto/prices', (_req, res) => {
  res.json([
    { coin: 'BTC', last: 345000, open: 340000 },
    { coin: 'ETH', last: 19500, open: 19200 },
    { coin: 'SOL', last: 1050, open: 1020 },
  ]);
});

app.get('/', (_req, res) => {
  res.json({
    service: 'AIBANK / server-goldbank',
    mode: 'DEMO',
    health: '/health',
    login: 'POST /api/auth/login { email: "demo@aibank.com.br" }',
  });
});

if (NODE_ENV !== 'test') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('[MODE] DEMO_MODE ativo — Necta/Azify desligados');
    console.log(`AIBANK API DEMO → porta ${PORT}`);
  });
}

module.exports = { app };
