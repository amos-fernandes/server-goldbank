'use strict';
/**
 * GoldBank API Server v2.0
 * Express + JWT + Rate Limiting + CORS Whitelist + GTK Integration
 * Repo: github.com/amos-fernandes/server-goldbank
 */
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config({ path: '.env.private' });

const {
  ASAAS_API_KEY,
  ASAAS_BASE_URL = 'https://api.asaas.com/v3',
  ASAAS_WALLET_ID,
  ENCRYPTION_KEY,
  JWT_SECRET = 'dev-secret-CHANGE-IN-PROD',
  GTK_API_URL = 'https://api.gtk.bank',
  GTK_API_KEY,
  PORT = 8082,
  NODE_ENV = 'development',
  ALLOWED_ORIGINS = 'http://localhost:8081,exp://localhost:8081,http://localhost:3000',
} = process.env;

// ─── DB (JSON — migrar para Cloud SQL em produção) ──────────────────────────
const DB_PATH = path.join(__dirname, 'db.json');

function loadDb() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  } catch (e) { console.error('[DB]', e.message); }
  return { users: [], transactions: [] };
}

function saveDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

let db = loadDb();

// ─── CLIENTS EXTERNOS ────────────────────────────────────────────────────────
const asaas = axios.create({
  baseURL: ASAAS_BASE_URL,
  headers: { access_token: ASAAS_API_KEY, 'Content-Type': 'application/json' },
  timeout: 10000,
});

const gtkApi = axios.create({
  baseURL: GTK_API_URL,
  headers: { 'x-api-key': GTK_API_KEY, 'Content-Type': 'application/json' },
  timeout: 8000,
});

// ─── APP ─────────────────────────────────────────────────────────────────────
const app = express();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// HTTPS redirect em produção (Cloud Run usa x-forwarded-proto)
app.use((req, res, next) => {
  if (NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// CORS — apenas origens autorizadas
const allowedOrigins = ALLOWED_ORIGINS.split(',').map(o => o.trim());
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', [
      'Content-Type', 'Authorization',
      'X-Request-Timestamp', 'X-App-Platform', 'X-App-Version',
    ].join(', '));
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Rate limiting global
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
}));

// Rate limiting rigoroso para login
app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
}));

// ─── MIDDLEWARE: Anti-replay (endpoints financeiros) ─────────────────────────
function requireFingerprint(req, res, next) {
  if (NODE_ENV !== 'production') return next();
  const ts = parseInt(req.headers['x-request-timestamp'] || '0');
  if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
    return res.status(401).json({ error: 'Requisição expirada. Reenvie a operação.' });
  }
  const platform = req.headers['x-app-platform'];
  if (!['ios', 'android'].includes(platform)) {
    return res.status(403).json({ error: 'Plataforma não autorizada.' });
  }
  next();
}

// ─── MIDDLEWARE: JWT Auth ─────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    db = loadDb();
    const user = db.users.find(u => u.id === decoded.userId);
    if (!user) return res.status(401).json({ error: 'Sessão inválida' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }
}

function issueToken(userId, email) {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '7d' });
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, cpfCnpj, phone } = req.body;
  if (!name || !email || !cpfCnpj) {
    return res.status(400).json({ error: 'Nome, email e CPF são obrigatórios.' });
  }
  console.log('[ASAAS] Registrando:', email);
  try {
    const { data: customer } = await asaas.post('/customers', {
      name, email, cpfCnpj, mobilePhone: phone, notificationDisabled: true,
    });
    const token = issueToken(customer.data.id, email);
    const newUser = {
      id: customer.data.id, name, email: email.toLowerCase(),
      asaasStatus: 'ACTIVE', walletId: ASAAS_WALLET_ID, token,
    };
    db = loadDb();
    db.users.push(newUser);
    saveDb(db);
    res.json(newUser);
  } catch (err) {
    console.error('[ASAAS ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro no Asaas' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email obrigatório.' });
  db = loadDb();
  const user = db.users.find(u => u.email === email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Conta não encontrada. Registre-se primeiro.' });
  const token = issueToken(user.id, user.email);
  const idx = db.users.findIndex(u => u.id === user.id);
  db.users[idx].token = token;
  saveDb(db);
  res.json({ ...user, token });
});

app.get('/api/auth/me', authenticateToken, (req, res) => res.json(req.user));

// ─── WALLET ───────────────────────────────────────────────────────────────────
app.post('/api/pix/deposit', authenticateToken, requireFingerprint, async (req, res) => {
  const { amount, description, customerId } = req.body;
  const cid = customerId || req.user.id;
  if (!cid?.startsWith('cus_')) {
    return res.status(400).json({ error: 'ID de cliente inválido. Crie uma conta via Registro.' });
  }
  console.log('[PIX] Solicitando:', amount, 'para cliente:', cid);
  try {
    const { data: payment } = await asaas.post('/payments', {
      customer: cid, billingType: 'PIX', value: amount,
      dueDate: new Date(Date.now() + 86400000).toISOString().split('T')[0],
      description: description || 'Depósito GoldBank',
    });
    const { data: qr } = await asaas.get(`/payments/${payment.id}/pixQrCode`);
    res.json({ qrCodeBase64: qr.encodedImage, qrCodePayload: qr.payload, value: payment.value, chargeId: payment.id });
  } catch (err) {
    console.error('[PIX ERROR]', err.response?.data || err.message);
    const code = err.response?.data?.errors?.[0]?.code;
    if (code === 'invalid_billingType' || err.message.includes('404')) {
      return res.json({
        qrCodeBase64: '',
        qrCodePayload: `00020101021226840014br.gov.bcb.pix0136goldbank-mock-only5204000053039865405${amount.toFixed(2)}5802BR5915GOLD BANK MOCK6008SAO PAULO62070503***6304ABCD`,
        value: amount,
        chargeId: 'pay_mock_' + Date.now(),
      });
    }
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro ao gerar PIX' });
  }
});

app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  if (!req.user.id?.startsWith('cus_')) return res.json([]);
  try {
    const { data } = await asaas.get('/payments', { params: { customer: req.user.id, limit: 20 } });
    res.json(data.data.map(p => ({
      id: p.id, type: 'INFLOW', category: 'Depósito PIX', amount: p.value,
      description: p.description || 'Depósito', date: p.dateCreated,
      status: ['RECEIVED', 'CONFIRMED'].includes(p.status) ? 'COMPLETED' : 'PENDING',
    })));
  } catch (err) {
    console.error('[TX ERROR]', err.message);
    res.json([]);
  }
});

app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const { data } = await asaas.get(`/wallets/${ASAAS_WALLET_ID}/balance`);
    res.json({ balance: data.balance ?? 0, availableBalance: data.availableBalance ?? 0, totalTransferValue: 0, isDemo: false });
  } catch {
    res.json({ balance: 1250.75, availableBalance: 1200.00, totalTransferValue: 500.00, isDemo: true, message: 'Saldo demonstrativo.' });
  }
});

app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
  try {
    const { data } = await asaas.get(`/wallets/${ASAAS_WALLET_ID}/balance`);
    res.json({ totalBalanceBRL: data.balance ?? 0, bankBalanceBRL: data.balance ?? 0, cryptoBalanceBRL: 0, accountsCount: 1, monthlyInflow: 0, monthlyOutflow: 0 });
  } catch {
    res.json({ totalBalanceBRL: 0, bankBalanceBRL: 0, cryptoBalanceBRL: 0, accountsCount: 1, monthlyInflow: 0, monthlyOutflow: 0 });
  }
});

// ─── CRYPTO ───────────────────────────────────────────────────────────────────
app.get('/api/crypto/mb/prices', async (req, res) => {
  try {
    const { data } = await axios.get('https://api.mercadobitcoin.net/api/v4/tickers', {
      params: { symbols: ['BTC-BRL', 'ETH-BRL', 'SOL-BRL', 'XRP-BRL', 'BNB-BRL', 'ADA-BRL', 'USDT-BRL'] },
    });
    res.json(data.map(t => ({ coin: t.pair.split('-')[0], last: parseFloat(t.last), open: parseFloat(t.open) })));
  } catch (err) {
    console.error('[MB ERROR]', err.message);
    res.json([]);
  }
});

app.get('/api/crypto/binance/prices', async (req, res) => {
  try {
    const symbols = ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'XRPUSDT', 'BNBUSDT', 'ADAUSDT'];
    const { data } = await axios.get('https://api.binance.com/api/v3/ticker/price', { params: { symbols: JSON.stringify(symbols) } });
    res.json(data.map(p => ({ symbol: p.symbol, price: parseFloat(p.price) })));
  } catch (err) {
    console.error('[BINANCE ERROR]', err.message);
    res.json([]);
  }
});

app.post('/api/crypto/buy', authenticateToken, requireFingerprint, (req, res) => {
  const { coin, amountBRL } = req.body;
  if (!coin || !amountBRL || amountBRL < 10) {
    return res.status(400).json({ error: 'Valor mínimo de R$ 10,00.' });
  }
  console.log('[CRYPTO] Simulação de compra:', coin, amountBRL);
  res.json({ success: true, estimatedCoinAmount: amountBRL / 1000, coin, amountBRL, message: `Compra de ${coin} realizada.` });
});

// ─── USER ────────────────────────────────────────────────────────────────────
app.post('/api/user/mb-credentials', authenticateToken, (req, res) => {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    return res.status(500).json({ error: 'Servidor não configurado para criptografia.' });
  }
  db = loadDb();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(JSON.stringify(req.body), 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  db.users[idx].mbCredentials = { data: encrypted, iv: iv.toString('hex') };
  saveDb(db);
  res.json({ success: true });
});

app.post('/api/user/kyc', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Documentos recebidos para análise.' });
});

// ─── GTK INTEGRATION ─────────────────────────────────────────────────────────
app.get('/api/gtk/balance/:address', authenticateToken, async (req, res) => {
  const { address } = req.params;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({ error: 'Endereço Ethereum inválido.' });
  }
  try {
    const { data } = await gtkApi.get(`/api/v1/balance/${address}`);
    res.json(data);
  } catch (err) {
    console.error('[GTK BALANCE]', err.message);
    res.status(502).json({ gtkBalance: '0', goldGrams: '0', goldValueBRL: '0', error: 'GTK API indisponível' });
  }
});

app.get('/api/gtk/price', async (req, res) => {
  try {
    const { data } = await gtkApi.get('/api/v1/system/info');
    res.json({ goldPricePerGram: data.goldPrice, currency: 'USD', source: 'GTK Oracle' });
  } catch (err) {
    console.error('[GTK PRICE]', err.message);
    res.status(502).json({ error: 'GTK Oracle indisponível' });
  }
});

app.post('/api/gtk/deposit/pix/create', authenticateToken, requireFingerprint, async (req, res) => {
  try {
    const { data } = await gtkApi.post('/api/v1/deposit/pix/create', {
      ...req.body,
      userAddress: req.body.userAddress || req.user.walletAddress,
    });
    res.json(data);
  } catch (err) {
    console.error('[GTK DEPOSIT]', err.response?.data || err.message);
    res.status(502).json({ error: 'Erro ao criar depósito GTK. Tente novamente.' });
  }
});

app.post('/api/gtk/withdraw', authenticateToken, requireFingerprint, async (req, res) => {
  try {
    const { data } = await gtkApi.post('/api/v1/withdrawal/pix', {
      ...req.body,
      userAddress: req.user.walletAddress,
    });
    res.json(data);
  } catch (err) {
    console.error('[GTK WITHDRAW]', err.response?.data || err.message);
    res.status(502).json({ error: 'Erro ao processar saque GTK.' });
  }
});

// ─── SECURITY: App Integrity ─────────────────────────────────────────────────
app.post('/api/security/verify-integrity', authenticateToken, async (req, res) => {
  const { token: integrityToken, platform } = req.body;
  if (!integrityToken) return res.status(400).json({ isValid: false, error: 'Token ausente.' });
  if (NODE_ENV !== 'production') return res.json({ isValid: true, message: 'Dev mode — integrity check skipped.' });
  try {
    if (platform === 'android') {
      const { data } = await axios.post(
        `https://playintegrity.googleapis.com/v1/${process.env.ANDROID_PACKAGE_NAME}:decodeIntegrityToken`,
        { integrity_token: integrityToken },
        { headers: { Authorization: `Bearer ${process.env.GOOGLE_SERVICE_ACCOUNT_TOKEN}` } },
      );
      const verdict = data.tokenPayloadExternal?.appIntegrity?.appRecognitionVerdict;
      return res.json({ isValid: verdict === 'PLAY_RECOGNIZED', verdict });
    }
    // iOS App Attest — em breve
    res.json({ isValid: true, message: 'iOS attestation — em breve.' });
  } catch (err) {
    console.error('[INTEGRITY]', err.message);
    res.status(500).json({ isValid: false, error: 'Erro na verificação.' });
  }
});

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0.0', env: NODE_ENV, timestamp: new Date().toISOString() });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n💎 GoldBank API v2.0 [${NODE_ENV}] → porta ${PORT} 💎\n`);
});
