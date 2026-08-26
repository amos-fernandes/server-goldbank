'use strict';
/**
 * AIBANK API Server v3.0
 * Express + JWT + PostgreSQL + NECTAco/Azify (Banking Core + PIX) + GTK Integration
 * Repo: github.com/amos-fernandes/server-goldbank
 */
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
require('dotenv').config({ path: '.env.private' });

const {
  NECTA_API_KEY,
  NECTA_BASE_URL = 'https://api.nectaco.com.br',
  NECTA_CLIENT_ID,
  NECTA_WEBHOOK_SECRET,
  AZIFY_API_KEY,
  AZIFY_BASE_URL = 'https://api.azify.com',
  AZIFY_CLIENT_ID,
  AZIFY_WEBHOOK_SECRET,
  ENCRYPTION_KEY,
  JWT_SECRET = 'dev-secret-CHANGE-IN-PROD',
  GTK_API_URL = 'https://gtk-api-529742420922.southamerica-east1.run.app',
  GTK_API_KEY,
  CREDIT_ENGINE_URL = 'http://localhost:8000',
  PORT = 8082,
  NODE_ENV = 'development',
  ALLOWED_ORIGINS = 'http://localhost:8081,exp://localhost:8081,http://localhost:19006,http://localhost:3000',
  DATABASE_URL,
} = process.env;

// ─── PostgreSQL (in-memory fallback when DATABASE_URL is not set) ─────────────
const USE_DB = !!DATABASE_URL;
const inMemoryUsers = new Map();

let pool = null;
if (USE_DB) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
} else {
  console.log('[DB] DATABASE_URL não configurado — usando memória (desenvolvimento/demo)');
}

async function initDb() {
  if (!USE_DB) return;
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        necta_status TEXT DEFAULT 'ACTIVE',
        necta_account_id TEXT,
        wallet_address TEXT,
        encrypted_private_key JSONB,
        kyc_status TEXT DEFAULT 'NOT_STARTED',
        kyc_document_id TEXT,
        kyc_submitted_at TIMESTAMPTZ,
        pix_keys JSONB DEFAULT '[]',
        mb_credentials JSONB,
        token TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    console.log('[DB] PostgreSQL conectado ✅ schema OK');
  } finally {
    client.release();
  }
}

async function findUserByEmail(email) {
  const key = email.toLowerCase();
  if (!USE_DB) {
    for (const u of inMemoryUsers.values()) {
      if (u.email === key) return u;
    }
    return null;
  }
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [key]);
  return rows[0] ? dbRowToUser(rows[0]) : null;
}

async function findUserById(id) {
  if (!USE_DB) {
    return inMemoryUsers.get(id) || null;
  }
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] ? dbRowToUser(rows[0]) : null;
}

async function insertUser(user) {
  if (!USE_DB) {
    inMemoryUsers.set(user.id, user);
    return;
  }
  await pool.query(
    `INSERT INTO users (id, name, email, password_hash, necta_status, necta_account_id,
      wallet_address, encrypted_private_key, kyc_status, pix_keys, token)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      user.id, user.name, user.email.toLowerCase(), user.passwordHash || null,
      user.nectaStatus, user.nectaAccountId, user.walletAddress,
      user.encryptedPrivateKey ? JSON.stringify(user.encryptedPrivateKey) : null,
      user.kycStatus || 'NOT_STARTED', JSON.stringify(user.pixKeys || []), user.token,
    ],
  );
}

async function updateUser(id, fields) {
  if (!USE_DB) {
    const user = inMemoryUsers.get(id);
    if (user) {
      const map = {
        token: 'token', kycStatus: 'kycStatus', kycDocumentId: 'kycDocumentId',
        kycSubmittedAt: 'kycSubmittedAt', walletAddress: 'walletAddress',
        pixKeys: 'pixKeys', mbCredentials: 'mbCredentials', nectaStatus: 'nectaStatus',
        passwordHash: 'passwordHash',
      };
      for (const [k, col] of Object.entries(map)) {
        if (k in fields) user[col] = fields[k];
      }
    }
    return;
  }
  const sets = [];
  const vals = [];
  let i = 1;
  const map = {
    token: 'token', kycStatus: 'kyc_status', kycDocumentId: 'kyc_document_id',
    kycSubmittedAt: 'kyc_submitted_at', walletAddress: 'wallet_address',
    pixKeys: 'pix_keys', mbCredentials: 'mb_credentials', nectaStatus: 'necta_status',
    passwordHash: 'password_hash',
  };
  for (const [k, col] of Object.entries(map)) {
    if (k in fields) {
      sets.push(`${col} = $${i++}`);
      const v = fields[k];
      vals.push(typeof v === 'object' && v !== null ? JSON.stringify(v) : v);
    }
  }
  if (!sets.length) return;
  vals.push(id);
  await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${i}`, vals);
}

function dbRowToUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    nectaStatus: row.necta_status,
    nectaAccountId: row.necta_account_id,
    walletAddress: row.wallet_address,
    encryptedPrivateKey: row.encrypted_private_key,
    kycStatus: row.kyc_status,
    kycDocumentId: row.kyc_document_id,
    kycSubmittedAt: row.kyc_submitted_at,
    pixKeys: row.pix_keys || [],
    mbCredentials: row.mb_credentials,
    token: row.token,
  };
}

// ─── HELPERS DE SEGURANÇA ────────────────────────────────────────────────────
function encryptValue(plaintext) {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(plaintext, 'utf-8', 'hex');
  encrypted += cipher.final('hex');
  return { data: encrypted, iv: iv.toString('hex') };
}

function decryptValue(encrypted) {
  if (!ENCRYPTION_KEY || !encrypted?.data || !encrypted?.iv) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(encrypted.iv, 'hex'));
    let dec = decipher.update(encrypted.data, 'hex', 'utf-8');
    dec += decipher.final('utf-8');
    return dec;
  } catch { return null; }
}

function detectPixKeyType(key) {
  const k = key.trim();
  if (/^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$/.test(k)) return 'EMAIL';
  const digits = k.replace(/\D/g, '');
  if (digits.length === 11 && !k.startsWith('+')) return 'CPF';
  if (digits.length === 14) return 'CNPJ';
  if (digits.length >= 10 && digits.length <= 13) return 'PHONE';
  return 'EVP';
}

function safeUser(user) {
  const { passwordHash, encryptedPrivateKey, mbCredentials, ...pub } = user;
  return pub;
}

// ─── CLIENTES EXTERNOS ────────────────────────────────────────────────────────
const necta = axios.create({
  baseURL: NECTA_BASE_URL,
  headers: {
    'Authorization': `Bearer ${NECTA_API_KEY}`,
    'Content-Type': 'application/json',
    'X-Client-ID': NECTA_CLIENT_ID,
  },
  timeout: 10000,
});

const azify = axios.create({
  baseURL: AZIFY_BASE_URL || 'https://api.azify.com',
  headers: {
    'Authorization': `Bearer ${AZIFY_API_KEY}`,
    'Content-Type': 'application/json',
    'X-Client-ID': AZIFY_CLIENT_ID,
  },
  timeout: 10000,
});

const gtkApi = axios.create({
  baseURL: GTK_API_URL,
  headers: { 'x-api-key': GTK_API_KEY, 'Content-Type': 'application/json' },
  timeout: 8000,
});

const creditEngine = axios.create({
  baseURL: CREDIT_ENGINE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// ─── PROVEDOR PIX ABSTRATO (Necta primary + Azify fallback) ───────────────────
class PixProvider {
  constructor() {
    this.primary = 'necta';
    this.fallback = 'azify';
    this.circuitOpen = false;
    this.failureCount = 0;
    this.lastFailure = 0;
    this.CIRCUIT_THRESHOLD = 3;
    this.CIRCUIT_RESET_MS = 60000;
  }

  _recordSuccess() { this.failureCount = 0; this.circuitOpen = false; }
  _recordFailure() {
    this.failureCount++;
    this.lastFailure = Date.now();
    if (this.failureCount >= this.CIRCUIT_THRESHOLD) {
      this.circuitOpen = true;
      console.warn(`[PIX] Circuit breaker OPEN — failing over to ${this.fallback}`);
    }
  }
  _shouldUseFallback() {
    if (!this.circuitOpen) return false;
    if (Date.now() - this.lastFailure > this.CIRCUIT_RESET_MS) {
      this.circuitOpen = false;
      this.failureCount = 0;
      console.log('[PIX] Circuit breaker RESET — trying primary again');
      return false;
    }
    return true;
  }
  async _try(provider, fn) {
    try {
      const result = await fn();
      if (provider === this.fallback) this._recordSuccess();
      return { success: true, data: result, provider };
    } catch (err) {
      if (provider === this.primary) this._recordFailure();
      throw err;
    }
  }

  async createPixDeposit({ amount, description, customerId, externalReference, expiresIn }) {
    const useFallback = this._shouldUseFallback();
    const first = useFallback ? this.fallback : this.primary;
    const second = useFallback ? this.primary : this.fallback;
    for (const provider of [first, second]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.post('/pre_venda', {
            titulo: 'Depósito AIBANK',
            descricao: description || `Depósito de R$ ${(amount / 100).toFixed(2)}`,
            amount: Math.round(amount),
            parcelamento_ate: 1, meio_pagamento: 3,
            data_expiracao: new Date(Date.now() + (expiresIn || 86400) * 1000).toISOString(),
            logo: true, split: false, juros: false, chargeProcessingFee: true,
            splits: [], repassarTaxaCliente: false,
          }));
          return {
            success: true, provider: 'necta',
            paymentLink: data.url || data.link,
            qrCodeBase64: data.qrCodeBase64 || '',
            qrCodePayload: data.qrCodePayload || data.pixCopiaECola || '',
            value: data.amount / 100, chargeId: data.id || data.preVendaId,
            expiresAt: data.data_expiracao,
          };
        } else {
          const { data } = await this._try('azify', () => azify.post('/v1/pix/charges', {
            amount, description: description || 'Depósito AIBANK',
            customerId, externalReference, expiresIn: expiresIn || 86400,
          }));
          return {
            success: true, provider: 'azify',
            paymentLink: data.paymentUrl, qrCodeBase64: data.qrCodeBase64,
            qrCodePayload: data.pixCopiaECola, value: data.amount / 100,
            chargeId: data.id, expiresAt: data.expiresAt,
          };
        }
      } catch (err) {
        if (provider === second) throw err;
      }
    }
    throw new Error('Todos provedores PIX falharam');
  }

  async createPixTransfer({ amount, pixKey, pixKeyType, description, accountId }) {
    const useFallback = this._shouldUseFallback();
    const first = useFallback ? this.fallback : this.primary;
    const second = useFallback ? this.primary : this.fallback;
    for (const provider of [first, second]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.post('/transferencias', {
            tipoTransferencia: 2, valor: amount,
            toEstabelecimentoId: null, contaBancariaId: null, senha: null,
            descricao: description || 'Envio via AIBANK', agendadoPara: null,
            pixKey: pixKey.trim(), pixKeyType,
          }));
          return { success: true, provider: 'necta', id: data.id, status: data.status, value: data.valor / 100 };
        } else {
          const { data } = await this._try('azify', () => azify.post('/v1/pix/transfers', {
            amount, pixKey: pixKey.trim(), pixKeyType,
            description: description || 'Envio via AIBANK', accountId,
          }));
          return { success: true, provider: 'azify', id: data.id, status: data.status, value: data.amount / 100 };
        }
      } catch (err) {
        if (provider === second) throw err;
      }
    }
    throw new Error('Todos provedores PIX transfer falharam');
  }

  async getAccountBalance(accountId) {
    for (const provider of [this.primary, this.fallback]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.get('/v2/bank-statement/daily-balance', {
            params: { 'rangeDate[gte]': new Date().toISOString().split('T')[0] + ' 00:00:00', 'rangeDate[lte]': new Date().toISOString().split('T')[0] + ' 23:59:59' },
          }));
          return { success: true, provider: 'necta', balance: data.saldoDisponivel || data.balance || data.availableBalance };
        } else {
          const { data } = await this._try('azify', () => azify.get(`/v1/accounts/${accountId}/balance`));
          return { success: true, provider: 'azify', balance: data.balance, availableBalance: data.availableBalance };
        }
      } catch (err) {
        if (provider === this.fallback) throw err;
      }
    }
    throw new Error('Balance falhou em todos provedores');
  }

  async getTransactions(accountId, params = {}) {
    for (const provider of [this.primary, this.fallback]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.get('/v2/bank-statement/list', { params: { page: 1, limit: params.limit || 30, detalhado: true, ...params } }));
          return { success: true, provider: 'necta', transactions: data.items || data };
        } else {
          const { data } = await this._try('azify', () => azify.get(`/v1/accounts/${accountId}/transactions`, { params }));
          return { success: true, provider: 'azify', transactions: data };
        }
      } catch (err) {
        if (provider === this.fallback) throw err;
      }
    }
    throw new Error('Transactions falhou em todos provedores');
  }

  async createCustomer(customerData) {
    for (const provider of [this.primary, this.fallback]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.post('/v1/customers', customerData));
          return { success: true, provider: 'necta', customer: data };
        } else {
          const { data } = await this._try('azify', () => azify.post('/v1/customers', customerData));
          return { success: true, provider: 'azify', customer: data };
        }
      } catch (err) {
        if (provider === this.fallback) throw err;
      }
    }
    throw new Error('Customer creation falhou em todos provedores');
  }

  async getKycStatus(customerId) {
    for (const provider of [this.primary, this.fallback]) {
      try {
        if (provider === 'necta') {
          const { data } = await this._try('necta', () => necta.get(`/v1/customers/${customerId}/kyc`));
          return { success: true, provider: 'necta', status: data.status };
        } else {
          const { data } = await this._try('azify', () => azify.get(`/v1/customers/${customerId}/kyc`));
          return { success: true, provider: 'azify', status: data.status };
        }
      } catch (err) {
        if (provider === this.fallback) throw err;
      }
    }
    throw new Error('KYC status falhou em todos provedores');
  }
}

const pixProvider = new PixProvider();

// ─── APP ─────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '25mb' }));

app.use((req, res, next) => {
  if (NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

const allowedOrigins = ALLOWED_ORIGINS.split(',').map(o => o.trim());
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', [
      'Content-Type', 'Authorization',
      'X-Request-Timestamp', 'X-App-Platform', 'X-App-Version',
    ].join(', '));
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
}));

app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
}));

app.use('/api/auth/register', rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  message: { error: 'Muitos cadastros neste IP. Aguarde 1 hora.' },
}));

// ─── MIDDLEWARE: Anti-replay ──────────────────────────────────────────────────
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
async function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    const user = await findUserById(decoded.userId);
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

// ─── DEMO USER ─────────────────────────────────────────────────────────────────
const DEMO_EMAIL = 'demo@aibank.com.br';
const DEMO_USER = {
  id: 'cus_demo_001',
  name: 'Usuário Demo',
  email: DEMO_EMAIL,
  passwordHash: null,
  nectaStatus: 'ACTIVE',
  nectaAccountId: 'acc_demo_001',
  walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18',
  encryptedPrivateKey: null,
  kycStatus: 'APPROVED',
  kycDocumentId: 'doc_demo_001',
  kycSubmittedAt: '2026-01-15T10:30:00Z',
  pixKeys: [
    { key: 'demo@pix.com', type: 'EMAIL', createdAt: '2026-01-10T08:00:00Z' },
    { key: '12345678901', type: 'CPF', createdAt: '2026-01-12T14:30:00Z' },
    { key: '+5511999999999', type: 'PHONE', createdAt: '2026-02-01T09:15:00Z' },
  ],
  token: null,
};

const DEMO_DASHBOARD = {
  totalBalanceBRL: 15234.56, bankBalanceBRL: 12345.67, cryptoBalanceBRL: 2888.89,
  accountsCount: 2, monthlyInflow: 8500.00, monthlyOutflow: 3200.00, provider: 'demo',
};

const DEMO_WALLET = {
  balance: 12345.67, availableBalance: 11890.00, totalTransferValue: 5200.00,
  isDemo: false, provider: 'demo',
};

const DEMO_TRANSACTIONS = [
  { id: 'tx_demo_001', type: 'INFLOW', category: 'Depósito PIX', amount: 2500.00, description: 'Depósito via PIX', date: '2026-08-24T14:30:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_002', type: 'OUTFLOW', category: 'PIX Enviado', amount: -150.00, description: 'Transferência para João', date: '2026-08-23T10:15:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_003', type: 'INFLOW', category: 'Compra GTK', amount: 500.00, description: 'Compra de Ouro Digital', date: '2026-08-22T16:45:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_004', type: 'OUTFLOW', category: 'PIX Enviado', amount: -800.00, description: 'Pagamento aluguel', date: '2026-08-20T09:00:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_005', type: 'INFLOW', category: 'Depósito PIX', amount: 3200.00, description: 'Salário', date: '2026-08-18T08:30:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_006', type: 'OUTFLOW', category: 'PIX Enviado', amount: -250.00, description: 'Conta de luz', date: '2026-08-17T11:20:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_007', type: 'INFLOW', category: 'Venda', amount: 1800.00, description: 'Venda de produto', date: '2026-08-15T15:00:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_008', type: 'OUTFLOW', category: 'PIX Enviado', amount: -120.00, description: 'Streamer Netflix', date: '2026-08-14T20:10:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_009', type: 'INFLOW', category: 'Depósito PIX', amount: 4500.00, description: 'Transferência recebida', date: '2026-08-12T13:45:00Z', status: 'COMPLETED', provider: 'demo' },
  { id: 'tx_demo_010', type: 'OUTFLOW', category: 'PIX Enviado', amount: -350.00, description: 'Freelancer design', date: '2026-08-10T17:30:00Z', status: 'COMPLETED', provider: 'demo' },
];

const DEMO_GTK_BALANCE = {
  gtkBalance: '5.234567', goldGrams: '5.234567', goldValueBRL: '2878.99',
  goldValueUSD: '527.09', goldPricePerGram: '550.00', provider: 'demo',
};

const DEMO_CRYPTO_PRICES_MB = [
  { coin: 'BTC', last: 345000.00, open: 340000.00 },
  { coin: 'ETH', last: 19500.00, open: 19200.00 },
  { coin: 'SOL', last: 1050.00, open: 1020.00 },
  { coin: 'XRP', last: 3.45, open: 3.30 },
  { coin: 'BNB', last: 3200.00, open: 3150.00 },
  { coin: 'ADA', last: 4.20, open: 4.10 },
  { coin: 'USDT', last: 5.50, open: 5.49 },
];

const DEMO_CRYPTO_PRICES_BINANCE = [
  { symbol: 'BTCUSDT', price: 62500.00 },
  { symbol: 'ETHUSDT', price: 3550.00 },
  { symbol: 'SOLUSDT', price: 190.00 },
  { symbol: 'XRPUSDT', price: 0.62 },
  { symbol: 'BNBUSDT', price: 580.00 },
  { symbol: 'ADAUSDT', price: 0.76 },
];

function isDemoUser(userId) { return userId === DEMO_USER.id; }
function isDemoEmail(email) { return email && email.toLowerCase() === DEMO_EMAIL; }
function demoQrPayload(amount) {
  const ts = Date.now();
  return `00020101021226840014br.gov.bcb.pix0136aibank-demo-${ts}5204000053039865405${amount.toFixed(2)}5802BR5915AIBANK DEMO6008SAO PAULO62070503***6304ABCD`;
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, cpfCnpj, phone, birthDate, address, addressNumber, neighborhood, postalCode, password } = req.body;
  if (!name || !email || !cpfCnpj || !phone || !birthDate || !address || !addressNumber || !neighborhood || !postalCode || !password) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Senha deve ter pelo menos 8 caracteres.' });
  }
  const normalizedEmail = email.toLowerCase().trim();
  console.log('[NECTA] Registrando:', normalizedEmail);
  try {
    const existing = await findUserByEmail(normalizedEmail);
    if (existing) {
      if (!existing.passwordHash) {
        return res.status(403).json({ error: 'Conta criada antes da atualização de segurança. Registre-se novamente.' });
      }
      const valid = await bcrypt.compare(password, existing.passwordHash);
      if (!valid) return res.status(401).json({ error: 'Senha incorreta.' });
      const token = issueToken(existing.id, existing.email);
      await updateUser(existing.id, { token });
      return res.json(safeUser({ ...existing, token }));
    }

    const { data: customer } = await necta.post('/v1/customers', {
      name, email: normalizedEmail, cpfCnpj: cpfCnpj.replace(/\D/g, ''),
      mobilePhone: phone.replace(/\D/g, ''), birthDate,
      address, addressNumber, complement: req.body.complement,
      neighborhood, postalCode: postalCode.replace(/\D/g, ''),
    });

    const passwordHash = await bcrypt.hash(password, 12);
    const token = issueToken(customer.id, normalizedEmail);
    const newUser = {
      id: customer.id, name, email: normalizedEmail, passwordHash,
      nectaStatus: customer.status || 'ACTIVE',
      nectaAccountId: customer.accountId,
      walletAddress: null, encryptedPrivateKey: null,
      kycStatus: 'NOT_STARTED', pixKeys: [], token,
    };
    await insertUser(newUser);
    console.log('[AUTH] Registro concluído:', normalizedEmail);
    res.json(safeUser(newUser));
  } catch (err) {
    console.error('[NECTA ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro no NECTAco' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email) return res.status(400).json({ error: 'Email obrigatório.' });

  // Demo login
  if (isDemoEmail(email)) {
    console.log('[DEMO] Login demo ativado');
    const token = issueToken(DEMO_USER.id, DEMO_USER.email);
    DEMO_USER.token = token;
    return res.json(safeUser(DEMO_USER));
  }

  try {
    const user = await findUserByEmail(email);
    if (!user) return res.status(401).json({ error: 'Conta não encontrada. Registre-se primeiro.' });

    if (!user.passwordHash) {
      return res.status(403).json({ error: 'Sua conta foi criada antes da atualização de segurança. Registre-se novamente.' });
    }
    if (password) {
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return res.status(401).json({ error: 'Senha incorreta.' });
    }

    const token = issueToken(user.id, user.email);
    await updateUser(user.id, { token });
    res.json(safeUser({ ...user, token }));
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    res.status(500).json({ error: 'Erro interno. Tente novamente.' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => res.json(safeUser(req.user)));

// ─── DEMO LOGIN (dedicado) ───────────────────────────────────────────────────
app.post('/api/auth/demo', async (req, res) => {
  console.log('[DEMO] Login demo ativado');
  const token = issueToken(DEMO_USER.id, DEMO_USER.email);
  DEMO_USER.token = token;
  res.json(safeUser(DEMO_USER));
});

// ─── WALLET ───────────────────────────────────────────────────────────────────
app.post('/api/pix/deposit', authenticateToken, requireFingerprint, async (req, res) => {
  const { amount, description } = req.body;
  const cid = req.user.id;
  if (!amount || amount < 1) return res.status(400).json({ error: 'Valor mínimo de R$ 1,00.' });

  if (isDemoUser(cid)) {
    return res.json({
      paymentLink: `https://pay.nectaco.com.br/demo/${Date.now()}`,
      qrCodeBase64: '', qrCodePayload: demoQrPayload(amount),
      value: amount, chargeId: 'demo_charge_' + Date.now(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(), provider: 'demo',
    });
  }

  try {
    const amountCents = Math.round(amount * 100);
    const result = await pixProvider.createPixDeposit({
      amount: amountCents,
      description: description || `Depósito de R$ ${amount.toFixed(2)} na carteira AIBANK`,
      customerId: cid, externalReference: `deposit:${cid}:${Date.now()}`, expiresIn: 86400,
    });
    res.json({
      paymentLink: result.paymentLink, qrCodeBase64: result.qrCodeBase64 || '',
      qrCodePayload: result.qrCodePayload || '', value: amount,
      chargeId: result.chargeId, expiresAt: result.expiresAt, provider: result.provider,
    });
  } catch (err) {
    console.error('[PIX DEPOSIT ERROR]', err.response?.data || err.message);
    if (NODE_ENV !== 'production') {
      return res.json({
        paymentLink: 'https://pay.nectaco.com.br/mock/' + Date.now(),
        qrCodeBase64: '', qrCodePayload: demoQrPayload(amount),
        value: amount, chargeId: 'mock_' + Date.now(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(), provider: 'mock',
      });
    }
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || err.message || 'Erro ao gerar PIX' });
  }
});

app.post('/api/pix/deposit-direct', authenticateToken, requireFingerprint, async (req, res) => {
  const { amount, description } = req.body;
  const cid = req.user.id;
  if (!amount || amount < 1) return res.status(400).json({ error: 'Valor mínimo de R$ 1,00.' });
  if (isDemoUser(cid)) {
    return res.json({ qrCodeBase64: '', qrCodePayload: demoQrPayload(amount), value: amount, chargeId: 'demo_direct_' + Date.now(), provider: 'demo' });
  }
  try {
    const result = await pixProvider.createPixDeposit({
      amount: Math.round(amount * 100), description: description || 'Depósito AIBANK',
      customerId: cid, externalReference: `deposit-direct:${cid}:${Date.now()}`, expiresIn: 86400,
    });
    res.json({ qrCodeBase64: result.qrCodeBase64 || '', qrCodePayload: result.qrCodePayload || '', value: amount, chargeId: result.chargeId, provider: result.provider });
  } catch (err) {
    console.error('[PIX DIRECT ERROR]', err.response?.data || err.message);
    if (NODE_ENV !== 'production') {
      return res.json({ qrCodeBase64: '', qrCodePayload: demoQrPayload(amount), value: amount, chargeId: 'mock_direct_' + Date.now(), provider: 'mock' });
    }
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro ao gerar PIX direto' });
  }
});

app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  if (isDemoUser(req.user.id)) return res.json(DEMO_TRANSACTIONS);
  try {
    const result = await pixProvider.getTransactions(req.user.nectaAccountId, { limit: 30 });
    const mapped = (result.transactions || []).map(t => ({
      id: t.id,
      type: (t.tipoTransacao === 'in' || t.tipoTransacao === 'Venda' || t.tipoTransacao === 'credit') ? 'INFLOW' : 'OUTFLOW',
      category: t.tipoTransacao === 'in' ? 'Depósito PIX' : t.tipoTransacao === 'Venda' ? 'Venda' : 'PIX Enviado',
      amount: t.valor ? t.valor / 100 : t.amount ? t.amount / 100 : 0,
      description: t.descricao || t.tipoTransacao || 'Transação',
      date: t.data || t.createdAt || t.dataLancamento,
      status: t.status === 'CONFIRMED' || t.status === 'COMPLETED' ? 'COMPLETED' : t.status === 'FAILED' || t.status === 'CANCELLED' ? 'FAILED' : 'PENDING',
      provider: result.provider,
    }));
    res.json(mapped);
  } catch (err) {
    console.error('[TX ERROR]', err.message);
    res.json([]);
  }
});

app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  if (isDemoUser(req.user.id)) return res.json(DEMO_WALLET);
  try {
    const result = await pixProvider.getAccountBalance(req.user.nectaAccountId);
    const balance = result.balance || 0;
    res.json({
      balance: typeof balance === 'number' ? balance : balance / 100,
      availableBalance: typeof balance === 'number' ? balance : balance / 100,
      totalTransferValue: 0, isDemo: false, provider: result.provider,
    });
  } catch {
    res.json({ balance: 0, availableBalance: 0, totalTransferValue: 0, isDemo: true, message: 'Saldo demonstrativo.' });
  }
});

app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
  if (isDemoUser(req.user.id)) return res.json(DEMO_DASHBOARD);
  try {
    const result = await pixProvider.getAccountBalance(req.user.nectaAccountId);
    const balance = result.balance || 0;
    const bal = typeof balance === 'number' ? balance : balance / 100;
    res.json({
      totalBalanceBRL: bal, bankBalanceBRL: bal, cryptoBalanceBRL: 0,
      accountsCount: 1, monthlyInflow: 0, monthlyOutflow: 0, provider: result.provider,
    });
  } catch {
    res.json({ totalBalanceBRL: 0, bankBalanceBRL: 0, cryptoBalanceBRL: 0, accountsCount: 1, monthlyInflow: 0, monthlyOutflow: 0 });
  }
});

// ─── CRYPTO ───────────────────────────────────────────────────────────────────
app.get('/api/crypto/mb/prices', async (req, res) => {
  if (req.query.demo === 'true' || req.headers['x-demo-mode'] === 'true') return res.json(DEMO_CRYPTO_PRICES_MB);
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
  if (req.query.demo === 'true' || req.headers['x-demo-mode'] === 'true') return res.json(DEMO_CRYPTO_PRICES_BINANCE);
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
  if (!coin || !amountBRL || amountBRL < 10) return res.status(400).json({ error: 'Valor mínimo de R$ 10,00.' });
  res.json({ success: true, estimatedCoinAmount: amountBRL / 1000, coin, amountBRL, message: `Compra de ${coin} realizada.` });
});

// ─── USER ────────────────────────────────────────────────────────────────────
app.post('/api/user/mb-credentials', authenticateToken, async (req, res) => {
  const enc = encryptValue(JSON.stringify(req.body));
  if (!enc) return res.status(500).json({ error: 'Servidor não configurado para criptografia.' });
  await updateUser(req.user.id, { mbCredentials: enc });
  res.json({ success: true });
});

app.post('/api/user/kyc', authenticateToken, async (req, res) => {
  const { frontBase64, backBase64, selfieBase64 } = req.body;
  if (!frontBase64 || !backBase64 || !selfieBase64) {
    return res.status(400).json({ error: 'Envie frente, verso e selfie do documento.' });
  }
  const customerId = req.user.id;
  if (isDemoUser(customerId)) {
    return res.json({ success: true, kycStatus: 'APPROVED', documentId: 'doc_demo_kyc', message: 'KYC aprovado automaticamente (modo demo).' });
  }
  if (req.user.kycStatus === 'APPROVED') {
    return res.status(400).json({ error: 'Identidade já verificada e aprovada.' });
  }
  try {
    const FormData = require('form-data');
    const identForm = new FormData();
    identForm.append('type', 'IDENTIFICATION');
    identForm.append('documentFile', Buffer.from(frontBase64, 'base64'), { filename: 'front.jpg', contentType: 'image/jpeg' });
    identForm.append('documentFileBack', Buffer.from(backBase64, 'base64'), { filename: 'back.jpg', contentType: 'image/jpeg' });
    const { data: identDoc } = await necta.post(`/v1/customers/${customerId}/documents`, identForm, { headers: identForm.getHeaders() });

    const selfieForm = new FormData();
    selfieForm.append('type', 'IDENTIFICATION');
    selfieForm.append('documentFile', Buffer.from(selfieBase64, 'base64'), { filename: 'selfie.jpg', contentType: 'image/jpeg' });
    await necta.post(`/v1/customers/${customerId}/documents`, selfieForm, { headers: selfieForm.getHeaders() })
      .catch(e => console.warn('[KYC] Selfie upload ignorado:', e.response?.data?.errors?.[0]?.description || e.message));

    await updateUser(req.user.id, { kycStatus: 'PENDING', kycDocumentId: identDoc.id, kycSubmittedAt: new Date().toISOString() });
    res.json({ success: true, kycStatus: 'PENDING', documentId: identDoc.id, message: 'Documentos enviados com sucesso. A análise leva até 24h.' });
  } catch (err) {
    console.error('[KYC ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro ao enviar documentos.' });
  }
});

app.get('/api/user/kyc-status', authenticateToken, async (req, res) => {
  const customerId = req.user.id;
  if (!customerId) return res.json({ kycStatus: req.user.kycStatus || 'NOT_STARTED' });
  if (isDemoUser(customerId)) {
    return res.json({ kycStatus: 'APPROVED', documents: [{ id: 'doc_demo_001', type: 'IDENTIFICATION', status: 'APPROVED' }] });
  }
  try {
    const { data } = await necta.get(`/v1/customers/${customerId}/kyc`);
    let kycStatus = req.user.kycStatus || 'NOT_STARTED';
    if (data.status === 'APPROVED') kycStatus = 'APPROVED';
    else if (data.status === 'REJECTED') kycStatus = 'REJECTED';
    else kycStatus = 'PENDING';
    if (kycStatus !== req.user.kycStatus) await updateUser(req.user.id, { kycStatus });
    res.json({ kycStatus, documents: data.documents || [] });
  } catch {
    res.json({ kycStatus: req.user.kycStatus || 'NOT_STARTED' });
  }
});

app.post('/api/user/wallet-address', authenticateToken, async (req, res) => {
  const { walletAddress } = req.body;
  if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
    return res.status(400).json({ error: 'Endereço Ethereum inválido.' });
  }
  await updateUser(req.user.id, { walletAddress });
  res.json({ success: true, walletAddress });
});

// ─── PIX CHAVES ───────────────────────────────────────────────────────────────
app.get('/api/user/pix-keys', authenticateToken, (req, res) => {
  if (isDemoUser(req.user.id)) return res.json(DEMO_USER.pixKeys);
  res.json(req.user.pixKeys || []);
});

app.post('/api/user/pix-key', authenticateToken, async (req, res) => {
  const { key } = req.body;
  if (!key?.trim()) return res.status(400).json({ error: 'Chave PIX inválida.' });
  const cleanKey = key.trim();
  const keyType = detectPixKeyType(cleanKey);
  const pixKeys = req.user.pixKeys || [];
  if (pixKeys.some(k => k.key === cleanKey)) return res.status(400).json({ error: 'Chave PIX já cadastrada.' });
  if (pixKeys.length >= 5) return res.status(400).json({ error: 'Limite de 5 chaves PIX atingido.' });
  const pixKey = { key: cleanKey, type: keyType, createdAt: new Date().toISOString() };
  await updateUser(req.user.id, { pixKeys: [...pixKeys, pixKey] });
  res.json({ success: true, pixKey });
});

app.delete('/api/user/pix-key/:key', authenticateToken, async (req, res) => {
  const keyToRemove = decodeURIComponent(req.params.key);
  const pixKeys = req.user.pixKeys || [];
  const newKeys = pixKeys.filter(k => k.key !== keyToRemove);
  if (newKeys.length === pixKeys.length) return res.status(404).json({ error: 'Chave não encontrada.' });
  await updateUser(req.user.id, { pixKeys: newKeys });
  res.json({ success: true });
});

app.get('/api/pix/lookup', authenticateToken, (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ error: 'Chave PIX não informada.' });
  const keyType = detectPixKeyType(String(key));
  const labels = { EMAIL: 'E-mail', CPF: 'CPF', CNPJ: 'CNPJ', PHONE: 'Telefone', EVP: 'Chave aleatória' };
  res.json({ key, keyType, keyTypeLabel: labels[keyType] || keyType, valid: true });
});

app.post('/api/pix/send', authenticateToken, requireFingerprint, async (req, res) => {
  const { pixKey, amount, description } = req.body;
  if (!pixKey || !amount || amount < 0.01) return res.status(400).json({ error: 'Chave PIX e valor são obrigatórios. Mínimo R$ 0,01.' });
  const keyType = detectPixKeyType(pixKey);

  if (isDemoUser(req.user.id)) {
    return res.json({ id: 'demo_pix_send_' + Date.now(), status: 'COMPLETED', value: amount, pixKey, keyType, provider: 'demo' });
  }

  try {
    const result = await pixProvider.createPixTransfer({
      amount: Math.round(amount * 100), pixKey: pixKey.trim(), pixKeyType: keyType,
      description: description || 'Envio via AIBANK', accountId: req.user.nectaAccountId,
    });
    res.json({ id: result.id, status: result.status, value: result.value, pixKey, keyType, provider: result.provider });
  } catch (err) {
    console.error('[PIX SEND ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || err.message || 'Erro ao enviar PIX.' });
  }
});

// ─── GTK INTEGRATION ─────────────────────────────────────────────────────────
app.get('/api/gtk/balance/:address', authenticateToken, async (req, res) => {
  const { address } = req.params;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return res.status(400).json({ error: 'Endereço Ethereum inválido.' });
  if (isDemoUser(req.user.id)) return res.json(DEMO_GTK_BALANCE);
  try {
    const [balanceRes, infoRes] = await Promise.all([
      gtkApi.get(`/api/v1/balance/${address}`),
      gtkApi.get('/api/v1/system/info'),
    ]);
    const b = balanceRes.data;
    const usdToBrl = infoRes.data.usdToBrl ?? 5.5;
    const goldValueUSD = parseFloat(b.estimatedUSDValue ?? '0');
    res.json({
      gtkBalance: b.gtkBalance, goldGrams: b.gtkBalance,
      goldValueBRL: (goldValueUSD * usdToBrl).toFixed(2),
      goldValueUSD: goldValueUSD.toFixed(2), goldPricePerGram: b.goldPricePerGram,
    });
  } catch (err) {
    console.error('[GTK BALANCE]', err.message);
    res.status(502).json({ gtkBalance: '0', goldGrams: '0', goldValueBRL: '0', goldValueUSD: '0', error: 'GTK API indisponível' });
  }
});

app.get('/api/gtk/price', async (req, res) => {
  if (req.query.demo === 'true' || req.headers['x-demo-mode'] === 'true') {
    return res.json({ goldPricePerGram: 550.00, currency: 'USD', source: 'GTK Oracle (Demo)' });
  }
  try {
    const { data } = await gtkApi.get('/api/v1/system/info');
    res.json({ goldPricePerGram: data.goldPrice, currency: 'USD', source: 'GTK Oracle' });
  } catch (err) {
    console.error('[GTK PRICE]', err.message);
    res.status(502).json({ error: 'GTK Oracle indisponível' });
  }
});

app.post('/api/gtk/deposit/pix/create', authenticateToken, requireFingerprint, async (req, res) => {
  const { amount } = req.body;
  const userAddress = req.user.walletAddress;
  if (!userAddress) return res.status(400).json({ error: 'Wallet ETH não encontrada. Registre novamente.' });
  if (!amount || amount < 1) return res.status(400).json({ error: 'Valor mínimo de R$ 1,00.' });

  if (isDemoUser(req.user.id)) {
    const goldPriceBRL = 550.00;
    const goldGrams = amount / goldPriceBRL;
    return res.json({
      paymentLink: `https://pay.nectaco.com.br/demo-gtk/${Date.now()}`,
      qrCodeBase64: '', qrCodePayload: demoQrPayload(amount),
      value: amount, chargeId: 'demo_gtk_charge_' + Date.now(),
      walletAddress: userAddress, externalReference: `gtk:${userAddress}`,
      goldGrams: goldGrams.toFixed(6), estimatedGTK: goldGrams.toFixed(6),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      goldPriceBRL: goldPriceBRL.toFixed(2), provider: 'demo',
    });
  }

  try {
    const { data: info } = await gtkApi.get('/api/v1/system/info');
    const goldPriceUSD = parseFloat(info.goldPrice ?? info.goldPricePerGram ?? 65);
    const usdToBrl = parseFloat(info.usdToBrl ?? 5.5);
    const goldPriceBRL = goldPriceUSD * usdToBrl;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const goldGrams = amount / goldPriceBRL;

    const { data: link } = await necta.post('/pre_venda', {
      titulo: 'Compra de GTK (Ouro Digital)',
      descricao: `Compra de ${amount.toFixed(2)} BRL em GTK — Ouro Digital AIBANK`,
      amount: Math.round(amount * 100), parcelamento_ate: 1, meio_pagamento: 3,
      data_expiracao: expiresAt, logo: true, split: false, juros: false,
      chargeProcessingFee: true, splits: [], repassarTaxaCliente: false,
    });
    res.json({
      paymentLink: link.url || link.link, qrCodeBase64: link.qrCodeBase64 || '',
      qrCodePayload: link.qrCodePayload || link.pixCopiaECola || '',
      value: amount, chargeId: link.id || link.preVendaId,
      walletAddress: userAddress, externalReference: `gtk:${userAddress}`,
      goldGrams: goldGrams.toFixed(6), estimatedGTK: goldGrams.toFixed(6),
      expiresAt, goldPriceBRL: goldPriceBRL.toFixed(2),
    });
  } catch (err) {
    console.error('[GTK DEPOSIT PIX]', err.response?.data || err.message);
    if (NODE_ENV !== 'production') {
      const goldPriceBRL = 65 * 5.5;
      return res.json({
        qrCodeBase64: '', qrCodePayload: demoQrPayload(amount),
        value: amount, chargeId: 'mock_gtk_' + Date.now(),
        walletAddress: userAddress, _mock: true, _message: 'Modo desenvolvimento.',
        goldGrams: (amount / goldPriceBRL).toFixed(6), estimatedGTK: (amount / goldPriceBRL).toFixed(6),
        expiresAt: new Date(Date.now() + 86400000).toISOString(), goldPriceBRL: goldPriceBRL.toFixed(2),
      });
    }
    res.status(502).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro ao criar depósito GTK.' });
  }
});

app.post('/api/gtk/withdraw', authenticateToken, requireFingerprint, async (req, res) => {
  try {
    const { data } = await gtkApi.post('/api/v1/withdrawal/pix', { ...req.body, userAddress: req.user.walletAddress });
    res.json(data);
  } catch (err) {
    console.error('[GTK WITHDRAW]', err.response?.data || err.message);
    res.status(502).json({ error: 'Erro ao processar saque GTK.' });
  }
});

app.post('/api/gtk/transfer', authenticateToken, requireFingerprint, async (req, res) => {
  const { toAddress, amount } = req.body;
  if (!/^0x[a-fA-F0-9]{40}$/.test(toAddress)) return res.status(400).json({ error: 'Endereço Ethereum inválido.' });
  const qty = parseFloat(amount);
  if (!qty || qty <= 0) return res.status(400).json({ error: 'Quantidade inválida.' });
  if (isDemoUser(req.user.id)) {
    return res.json({ txHash: '0xdemo' + Date.now().toString(16), from: DEMO_USER.walletAddress, to: toAddress, amount: qty.toString(), status: 'COMPLETED', provider: 'demo' });
  }
  if (!req.user.encryptedPrivateKey || !req.user.walletAddress) {
    return res.status(400).json({ error: 'Carteira custodial não encontrada. Refaça o cadastro.' });
  }
  try {
    const { ethers } = require('ethers');
    const privateKey = decryptValue(req.user.encryptedPrivateKey);
    if (!privateKey) return res.status(500).json({ error: 'Erro ao acessar carteira. Contate o suporte.' });
    const ethRpcUrl = process.env.ETH_RPC_URL || 'https://eth.llamarpc.com';
    const gtkTokenAddress = process.env.GTK_TOKEN_ADDRESS || '0x8751264B0f82cfE5DD3ad941b4d28FD7a0f896EA';
    const provider = new ethers.JsonRpcProvider(ethRpcUrl);
    const wallet = new ethers.Wallet(privateKey, provider);
    const token = new ethers.Contract(gtkTokenAddress, ['function transfer(address to, uint256 amount) returns (bool)'], wallet);
    const tx = await token.transfer(toAddress, ethers.parseEther(qty.toString()));
    res.json({ txHash: tx.hash, from: req.user.walletAddress, to: toAddress, amount: qty.toString(), status: 'PENDING' });
  } catch (err) {
    console.error('[GTK TRANSFER ERROR]', err.message);
    res.status(502).json({ error: 'Erro ao enviar GTK: ' + (err.shortMessage || err.message) });
  }
});

// ─── WEBHOOKS ─────────────────────────────────────────────────────────────────
app.post('/api/kyc/webhook', async (req, res) => {
  const nectaToken = req.headers['necta-webhook-secret'] || req.headers['x-necta-signature'];
  const azifyToken = req.headers['azify-webhook-secret'] || req.headers['x-azify-signature'];
  const isNecta = NECTA_WEBHOOK_SECRET && nectaToken === NECTA_WEBHOOK_SECRET;
  const isAzify = AZIFY_WEBHOOK_SECRET && azifyToken === AZIFY_WEBHOOK_SECRET;
  if (!isNecta && !isAzify) return res.sendStatus(401);
  res.sendStatus(200);

  const event = req.body;
  let customerId = null, kycStatus = null;
  if (isNecta) {
    if (event?.event !== 'customer.kyc.updated') return;
    customerId = event?.customer?.id;
    kycStatus = event?.kyc?.status;
  } else {
    customerId = event?.customer?.id || event?.data?.customer?.id;
    kycStatus = event?.kyc?.status || event?.data?.status;
  }
  if (!customerId || !kycStatus) return;
  let status = 'PENDING';
  if (kycStatus === 'APPROVED') status = 'APPROVED';
  else if (kycStatus === 'REJECTED') status = 'REJECTED';

  try {
    if (USE_DB) {
      const { rows } = await pool.query('SELECT id FROM users WHERE id = $1', [customerId]);
      if (rows.length) await updateUser(customerId, { kycStatus: status });
    } else {
      if (inMemoryUsers.has(customerId)) await updateUser(customerId, { kycStatus: status });
    }
  } catch (err) {
    console.error('[KYC WEBHOOK ERROR]', err.message);
  }
});

app.post('/api/pix/webhook', async (req, res) => {
  const nectaToken = req.headers['necta-webhook-secret'] || req.headers['x-necta-signature'];
  const azifyToken = req.headers['azify-webhook-secret'] || req.headers['x-azify-signature'];
  const isNecta = NECTA_WEBHOOK_SECRET && nectaToken === NECTA_WEBHOOK_SECRET;
  const isAzify = AZIFY_WEBHOOK_SECRET && azifyToken === AZIFY_WEBHOOK_SECRET;
  if (!isNecta && !isAzify) return res.sendStatus(401);
  res.sendStatus(200);

  const event = req.body;
  let charge = null;
  if (isNecta) {
    charge = event?.charge;
    if (!charge || charge.status !== 'PAID') return;
  } else {
    charge = event?.data?.charge || event?.charge;
    if (!charge || charge.status !== 'paid') return;
  }
  if (!charge.externalReference?.startsWith('gtk:')) return;
  const walletAddress = charge.externalReference.replace('gtk:', '');
  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) return;

  try {
    const { data: info } = await gtkApi.get('/api/v1/system/info');
    const goldPriceBRL = parseFloat(info.goldPrice ?? info.goldPricePerGram ?? 0) * parseFloat(info.usdToBrl ?? 5.5);
    if (!goldPriceBRL) return;
    const amountBRL = charge.amount || charge.value;
    const gtkAmount = (amountBRL / goldPriceBRL).toFixed(6);
    await gtkApi.post('/api/v1/deposit/pix/webhook', {
      walletAddress, amount: gtkAmount, amountBRL,
      pixId: charge.id, status: charge.status, externalReference: charge.externalReference,
    });
    console.log(`[WEBHOOK] ✅ GTK mint: ${gtkAmount} GTK → ${walletAddress} (via ${isNecta ? 'Necta' : 'Azify'})`);
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.response?.data || err.message);
  }
});

// ─── CRÉTIDO (Node.js proxy → Python Credit Engine) ──────────────────────────
app.post('/api/credit/analyze', authenticateToken, async (req, res) => {
  try {
    const { customer_id, lookback_days = 180 } = req.body;
    const cid = customer_id || req.user.id;

    // Usuário demo: retorna mock de crédito
    if (isDemoUser(req.user)) {
      return res.json({
        customer_id: cid,
        score: 720,
        probability_of_default: 0.12,
        decision: 'approve',
        suggested_credit_limit: 15000.00,
        reasons: ['conta_estabelecida', 'alto_volume_transacional', 'entradas_regulares'],
        model_version: 'demo-v1.0.0',
        generated_at: new Date().toISOString(),
        lstm_risk_score: 0.18,
        scorecard_score: 720,
      });
    }

    const response = await creditEngine.post('/credit/analyze', {
      customer_id: cid,
      lookback_days,
    });
    res.json(response.data);
  } catch (err) {
    console.error('[CREDIT ANALYZE ERROR]', err.response?.data || err.message);
    res.status(502).json({ error: 'Erro ao consultar motor de crédito.', detail: err.response?.data || err.message });
  }
});

app.get('/api/credit/status', authenticateToken, async (req, res) => {
  try {
    if (isDemoUser(req.user)) {
      return res.json({
        customer_id: req.user.id,
        status: 'APPROVED',
        score: 720,
        decision: 'approve',
        approved_limit: 15000.00,
        available_limit: 15000.00,
        reasons: [],
        analyzed_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      });
    }

    const response = await creditEngine.get(`/credit/status/${req.user.id}`);
    res.json(response.data);
  } catch (err) {
    console.error('[CREDIT STATUS ERROR]', err.response?.data || err.message);
    res.json({ customer_id: req.user.id, status: 'NOT_STARTED' });
  }
});

app.get('/api/credit/limit', authenticateToken, async (req, res) => {
  try {
    if (isDemoUser(req.user)) {
      return res.json({
        customer_id: req.user.id,
        approved_limit: 15000.00,
        available_limit: 15000.00,
        used_limit: 0.00,
        status: 'APPROVED',
      });
    }

    const response = await creditEngine.get(`/credit/limit/${req.user.id}`);
    res.json(response.data);
  } catch (err) {
    console.error('[CREDIT LIMIT ERROR]', err.response?.data || err.message);
    res.json({ customer_id: req.user.id, approved_limit: 0, available_limit: 0, used_limit: 0, status: 'NOT_STARTED' });
  }
});

app.post('/api/credit/simulate', authenticateToken, async (req, res) => {
  try {
    const { amount, installments = 12, monthly_rate = 0.0199 } = req.body;

    if (!amount || amount <= 0) return res.status(400).json({ error: 'Valor inválido.' });

    // Simulação local (Tabela Price) — rápido, sem chamar Python
    const n = installments;
    const r = monthly_rate;
    const installment_value = r > 0
      ? amount * (r * Math.pow(1 + r, n)) / (Math.pow(1 + r, n) - 1)
      : amount / n;
    const total_cost = installment_value * n;
    const total_interest = total_cost - amount;
    const effective_annual = (Math.pow(1 + r, 12) - 1) * 100;

    res.json({
      amount,
      installments: n,
      monthly_rate: r,
      installment_value: Math.round(installment_value * 100) / 100,
      total_cost: Math.round(total_cost * 100) / 100,
      total_interest: Math.round(total_interest * 100) / 100,
      effective_annual_rate: Math.round(effective_annual * 100) / 100,
    });
  } catch (err) {
    console.error('[CREDIT SIMULATE ERROR]', err.message);
    res.status(500).json({ error: 'Erro na simulação.' });
  }
});

// ─── SECURITY ────────────────────────────────────────────────────────────────
app.post('/api/security/verify-integrity', authenticateToken, async (req, res) => {
  const { token: integrityToken, platform } = req.body;
  if (!integrityToken) return res.status(400).json({ isValid: false, error: 'Token ausente.' });
  if (NODE_ENV !== 'production') return res.json({ isValid: true, message: 'Dev mode — integrity check skipped.' });
  res.json({ isValid: true, message: 'iOS/Android attestation — em breve.' });
});

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  let dbOk = false;
  if (USE_DB) {
    try { await pool.query('SELECT 1'); dbOk = true; } catch {}
  } else {
    dbOk = true;
  }
  res.json({ status: 'ok', version: '3.0.0', env: NODE_ENV, db: dbOk ? 'ok' : 'memory', mode: USE_DB ? 'postgresql' : 'in-memory', timestamp: new Date().toISOString() });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

// ─── START ───────────────────────────────────────────────────────────────────
if (NODE_ENV !== 'test') {
  initDb()
    .then(() => {
      app.listen(PORT, '0.0.0.0', () => {
        console.log(`\n💎 AIBANK API v3.0 [${NODE_ENV}] → porta ${PORT} 💎\n`);
      });
    })
    .catch(err => {
      console.error('[DB FATAL]', err.message);
      process.exit(1);
    });
}

module.exports = { app, necta, azify, gtkApi, creditEngine };
