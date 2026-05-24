'use strict';
/**
 * GoldBank API Server v3.0
 * Express + JWT + bcrypt + PostgreSQL + Asaas Subaccounts + GTK Integration
 * Repo: github.com/amos-fernandes/server-goldbank
 */
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
require('dotenv').config({ path: '.env.private' });

const {
  ASAAS_API_KEY,
  ASAAS_BASE_URL = 'https://api.asaas.com/v3',
  ASAAS_WEBHOOK_TOKEN,           // Token de autenticação cadastrado no painel Asaas
  ENCRYPTION_KEY,
  JWT_SECRET = 'dev-secret-CHANGE-IN-PROD',
  GTK_API_URL = 'https://api.gtk.bank',
  GTK_API_KEY,
  PORT = 8082,
  NODE_ENV = 'development',
  ALLOWED_ORIGINS = 'http://localhost:8081,exp://localhost:8081,http://localhost:3000',
  DATABASE_URL,
} = process.env;

// ─── BANCO DE DADOS (PostgreSQL) ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id                  TEXT PRIMARY KEY,
      name                TEXT NOT NULL,
      email               TEXT UNIQUE NOT NULL,
      password_hash       TEXT,
      asaas_account_id    TEXT,
      asaas_wallet_id     TEXT,
      asaas_api_key       TEXT,
      asaas_customer_id   TEXT,
      asaas_status        TEXT DEFAULT 'PENDING',
      wallet_address      TEXT,
      mb_credentials_data TEXT,
      mb_credentials_iv   TEXT,
      last_login_at       TIMESTAMPTZ,
      created_at          TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('[DB] Tabelas prontas.');
}

// Converte row do PostgreSQL para objeto JS camelCase
function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    asaasAccountId: row.asaas_account_id,
    asaasWalletId: row.asaas_wallet_id,
    asaasApiKey: row.asaas_api_key,
    asaasCustomerId: row.asaas_customer_id,
    asaasStatus: row.asaas_status,
    walletAddress: row.wallet_address,
    mbCredentials: row.mb_credentials_data
      ? { data: row.mb_credentials_data, iv: row.mb_credentials_iv }
      : undefined,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
  };
}

// ─── HELPERS DE SEGURANÇA ────────────────────────────────────────────────────
function encrypt(text) {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) return text;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let enc = cipher.update(text, 'utf-8', 'hex');
  enc += cipher.final('hex');
  return iv.toString('hex') + ':' + enc;
}

function decrypt(text) {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64 || !text?.includes(':')) return text;
  const [ivHex, enc] = text.split(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(ivHex, 'hex'));
  let dec = decipher.update(enc, 'hex', 'utf-8');
  dec += decipher.final('utf-8');
  return dec;
}

function safeUser(user) {
  const { passwordHash, asaasApiKey, mbCredentials, ...safe } = user;
  return safe;
}

function mapAccountStatus(raw) {
  const s = typeof raw === 'object' ? raw?.status : raw;
  if (s === 'ACTIVE' || s === 'APPROVED') return 'ACTIVE';
  if (s === 'REJECTED' || s === 'INACTIVE' || s === 'DISABLED') return 'REJECTED';
  return 'PENDING';
}

// ─── CLIENTES AXIOS ──────────────────────────────────────────────────────────
const asaas = axios.create({
  baseURL: ASAAS_BASE_URL,
  headers: { access_token: ASAAS_API_KEY, 'Content-Type': 'application/json' },
  timeout: 15000,
});

const gtkApi = axios.create({
  baseURL: GTK_API_URL,
  headers: { 'x-api-key': GTK_API_KEY, 'Content-Type': 'application/json' },
  timeout: 8000,
});

function makeSubAsaas(encryptedApiKey) {
  const key = decrypt(encryptedApiKey);
  return axios.create({
    baseURL: ASAAS_BASE_URL,
    headers: { access_token: key, 'Content-Type': 'application/json' },
    timeout: 15000,
  });
}

// ─── APP ─────────────────────────────────────────────────────────────────────
const app = express();

// Render (e qualquer PaaS) senta atrás de um reverse proxy.
// Sem isso o express-rate-limit rejeita X-Forwarded-For com ValidationError.
app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '1mb' }));

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
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', [
      'Content-Type', 'Authorization',
      'X-Request-Timestamp', 'X-App-Platform', 'X-App-Version',
    ].join(', '));
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
}));

app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Muitas tentativas de login. Aguarde 15 minutos.' },
}));

app.use('/api/auth/register', rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Muitos cadastros neste IP. Aguarde 1 hora.' },
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
async function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    const user = rowToUser(rows[0]);
    if (!user) return res.status(401).json({ error: 'Sessão inválida' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' });
  }
}

function requireSubAccount(req, res, next) {
  if (!req.user.asaasApiKey) {
    return res.status(403).json({
      error: 'Conta criada antes da atualização do sistema. Por favor, registre-se novamente para ativar sua carteira individual.',
    });
  }
  next();
}

function issueToken(userId, email) {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '7d' });
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const {
    name, email, cpfCnpj, phone, birthDate,
    address, addressNumber, complement, neighborhood, postalCode, password,
  } = req.body;

  if (!name || !email || !cpfCnpj || !phone || !birthDate || !address || !addressNumber || !neighborhood || !postalCode || !password) {
    return res.status(400).json({ error: 'Todos os campos obrigatórios devem ser preenchidos.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Senha deve ter no mínimo 8 caracteres.' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const { rows: existing } = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
  if (existing.length > 0) {
    return res.status(409).json({ error: 'E-mail já cadastrado.' });
  }

  const cleanCpf = cpfCnpj.replace(/\D/g, '');

  console.log('[ASAAS] Criando subconta para:', normalizedEmail);

  try {
    const { data: account } = await asaas.post('/accounts', {
      name,
      email,
      cpfCnpj: cleanCpf,
      mobilePhone: phone.replace(/\D/g, ''),
      birthDate,
      address,
      addressNumber,
      complement: complement || undefined,
      province: neighborhood,
      postalCode: postalCode.replace(/\D/g, ''),
      companyType: cleanCpf.length === 14 ? 'LIMITED' : undefined,
    });

    if (!account.apiKey) {
      throw new Error('Asaas não retornou a chave da subconta. Tente novamente.');
    }

    console.log(`[ASAAS] Subconta criada: ${account.id} | Wallet: ${account.walletId}`);

    const subAsaas = makeSubAsaas(account.apiKey);
    const { data: customer } = await subAsaas.post('/customers', {
      name,
      email,
      cpfCnpj: cleanCpf,
      mobilePhone: phone.replace(/\D/g, ''),
      notificationDisabled: true,
    });

    console.log(`[ASAAS] Customer da subconta: ${customer.id}`);

    const passwordHash = await bcrypt.hash(password, 12);
    const encryptedApiKey = encrypt(account.apiKey);
    const asaasStatus = mapAccountStatus(account.accountStatus);

    await pool.query(
      `INSERT INTO users
        (id, name, email, password_hash, asaas_account_id, asaas_wallet_id,
         asaas_api_key, asaas_customer_id, asaas_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [account.id, name, normalizedEmail, passwordHash, account.id,
       account.walletId, encryptedApiKey, customer.id, asaasStatus],
    );

    const token = issueToken(account.id, normalizedEmail);
    console.log(`[AUTH] Registro concluído: ${normalizedEmail}`);

    res.status(201).json({
      id: account.id, name, email: normalizedEmail,
      asaasAccountId: account.id, asaasWalletId: account.walletId,
      asaasStatus, walletId: account.walletId, token,
    });
  } catch (err) {
    const asaasMsg = err.response?.data?.errors?.[0]?.description;
    console.error('[ASAAS REGISTER ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: asaasMsg || err.message || 'Erro ao criar conta no Asaas.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
  }

  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
  const user = rowToUser(rows[0]);

  if (!user) {
    return res.status(401).json({ error: 'Conta não encontrada. Verifique o e-mail.' });
  }

  if (!user.passwordHash) {
    return res.status(403).json({
      error: 'Sua conta foi criada antes da atualização de segurança. Por favor, registre-se novamente.',
    });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: 'Senha incorreta.' });
  }

  await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

  const token = issueToken(user.id, user.email);
  console.log(`[AUTH] Login: ${user.email}`);
  res.json({ ...safeUser(user), walletId: user.asaasWalletId, token });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ ...safeUser(req.user), walletId: req.user.asaasWalletId });
});

// ─── WALLET ───────────────────────────────────────────────────────────────────
app.get('/api/wallet/balance', authenticateToken, requireSubAccount, async (req, res) => {
  try {
    const userAsaas = makeSubAsaas(req.user.asaasApiKey);
    const { data } = await userAsaas.get('/finance/balance');
    res.json({
      balance: data.balance ?? 0,
      availableBalance: data.availableBalance ?? data.balance ?? 0,
      walletId: req.user.asaasWalletId,
      isDemo: false,
    });
  } catch (err) {
    console.error('[BALANCE ERROR]', err.response?.data || err.message);
    res.json({ balance: 0, availableBalance: 0, isDemo: true, message: 'Saldo temporariamente indisponível.' });
  }
});

app.post('/api/pix/deposit', authenticateToken, requireSubAccount, requireFingerprint, async (req, res) => {
  const { amount, description } = req.body;
  if (!amount || amount < 1) {
    return res.status(400).json({ error: 'Valor mínimo de R$ 1,00.' });
  }

  console.log(`[PIX] Gerando cobrança R$${amount} para subconta: ${req.user.asaasAccountId}`);

  try {
    const userAsaas = makeSubAsaas(req.user.asaasApiKey);
    const { data: payment } = await userAsaas.post('/payments', {
      customer: req.user.asaasCustomerId,
      billingType: 'PIX',
      value: amount,
      dueDate: new Date(Date.now() + 86400000).toISOString().split('T')[0],
      description: description || 'Depósito GoldBank',
    });

    const { data: qr } = await userAsaas.get(`/payments/${payment.id}/pixQrCode`);

    console.log(`[PIX] Cobrança criada: ${payment.id}`);
    res.json({
      qrCodeBase64: qr.encodedImage,
      qrCodePayload: qr.payload,
      value: payment.value,
      chargeId: payment.id,
    });
  } catch (err) {
    console.error('[PIX ERROR]', err.response?.data || err.message);
    res.status(400).json({ error: err.response?.data?.errors?.[0]?.description || 'Erro ao gerar PIX.' });
  }
});

app.get('/api/wallet/transactions', authenticateToken, requireSubAccount, async (req, res) => {
  try {
    const userAsaas = makeSubAsaas(req.user.asaasApiKey);
    const { data } = await userAsaas.get('/payments', {
      params: { customer: req.user.asaasCustomerId, limit: 20, offset: 0 },
    });
    res.json(data.data.map(p => ({
      id: p.id,
      type: 'INFLOW',
      category: 'Depósito PIX',
      amount: p.value,
      description: p.description || 'Depósito',
      date: p.dateCreated,
      status: ['RECEIVED', 'CONFIRMED'].includes(p.status) ? 'COMPLETED' : 'PENDING',
    })));
  } catch (err) {
    console.error('[TX ERROR]', err.message);
    res.json([]);
  }
});

app.get('/api/dashboard/summary', authenticateToken, requireSubAccount, async (req, res) => {
  try {
    const userAsaas = makeSubAsaas(req.user.asaasApiKey);
    const { data } = await userAsaas.get('/finance/balance');
    res.json({
      totalBalanceBRL: data.balance ?? 0,
      bankBalanceBRL: data.balance ?? 0,
      cryptoBalanceBRL: 0,
      accountsCount: 1,
      monthlyInflow: 0,
      monthlyOutflow: 0,
    });
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
app.post('/api/user/mb-credentials', authenticateToken, async (req, res) => {
  if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    return res.status(500).json({ error: 'Servidor não configurado para criptografia.' });
  }
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(JSON.stringify(req.body), 'utf-8', 'hex');
  encrypted += cipher.final('hex');

  await pool.query(
    'UPDATE users SET mb_credentials_data = $1, mb_credentials_iv = $2 WHERE id = $3',
    [encrypted, iv.toString('hex'), req.user.id],
  );
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
    res.json({ isValid: true, message: 'iOS attestation — em breve.' });
  } catch (err) {
    console.error('[INTEGRITY]', err.message);
    res.status(500).json({ isValid: false, error: 'Erro na verificação.' });
  }
});

// ─── WEBHOOK: Validação de Saque (Asaas pergunta: "posso liberar?") ──────────
// Asaas chama este endpoint ANTES de processar qualquer saque da conta
// Deve responder em até 10s — se não responder, Asaas NEGA o saque por padrão
app.post('/api/pix/withdraw/validate', async (req, res) => {
  // 1. Validar IP do Asaas
  if (!isAsaasIP(req)) {
    console.warn('[WITHDRAW-VALIDATE] IP não autorizado:', req.headers['x-forwarded-for'] || req.socket.remoteAddress);
    return res.status(403).json({ authorized: false });
  }

  // 2. Validar token de autenticação (se configurado no painel Asaas)
  const token = req.headers['asaas-access-token'] || req.body?.accessToken;
  if (ASAAS_WEBHOOK_TOKEN && token !== ASAAS_WEBHOOK_TOKEN) {
    console.warn('[WITHDRAW-VALIDATE] Token inválido');
    return res.status(401).json({ authorized: false });
  }

  const { id, value, type, walletId, description } = req.body;
  console.log(`[WITHDRAW-VALIDATE] Saque solicitado: R$${value} | Tipo: ${type} | ID: ${id}`);

  // 3. Regras de negócio — ajuste conforme necessário
  try {
    // Negar saques acima de R$ 50.000 sem revisão manual
    if (value > 50000) {
      console.warn(`[WITHDRAW-VALIDATE] ❌ Valor acima do limite: R$${value}`);
      return res.json({ authorized: false, reason: 'Valor acima do limite automático. Contate o suporte.' });
    }

    // Verificar horário (bloquear madrugada 23h–6h como proteção antifraude)
    const hour = new Date().getHours(); // UTC — Brasília = UTC-3
    const hourBR = (hour - 3 + 24) % 24;
    if (hourBR >= 23 || hourBR < 6) {
      console.warn(`[WITHDRAW-VALIDATE] ❌ Fora do horário permitido: ${hourBR}h`);
      return res.json({ authorized: false, reason: 'Saques não permitidos entre 23h e 6h (horário de Brasília).' });
    }

    // Autorizar
    console.log(`[WITHDRAW-VALIDATE] ✅ Autorizado: R$${value}`);
    res.json({ authorized: true });

  } catch (err) {
    console.error('[WITHDRAW-VALIDATE] Erro interno:', err.message);
    // Em caso de erro interno, NEGAR por segurança
    res.json({ authorized: false, reason: 'Erro interno. Tente novamente.' });
  }
});

// ─── WEBHOOK ASAAS ───────────────────────────────────────────────────────────
// IPs oficiais Asaas: 177.153.18.0/24 e 177.153.19.0/24
const ASAAS_IPS = ['177.153.18.', '177.153.19.'];

function isAsaasIP(req) {
  if (NODE_ENV !== 'production') return true; // libera em dev
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  return ASAAS_IPS.some(prefix => ip.startsWith(prefix));
}

app.post('/api/pix/webhook', async (req, res) => {
  if (!isAsaasIP(req)) {
    console.warn('[WEBHOOK] IP não autorizado:', req.headers['x-forwarded-for'] || req.socket.remoteAddress);
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { event, payment } = req.body;
  console.log(`[WEBHOOK] Evento: ${event} | Cobrança: ${payment?.id} | Status: ${payment?.status}`);

  // Pagamento confirmado
  if (event === 'PAYMENT_RECEIVED' || event === 'PAYMENT_CONFIRMED') {
    try {
      // Registrar pagamento confirmado no banco para auditoria
      await pool.query(
        `INSERT INTO transactions (id, user_id, type, category, amount_brl, description, status, asaas_charge_id)
         VALUES ($1,
           (SELECT id FROM users WHERE asaas_customer_id = $2 LIMIT 1),
           'INFLOW', 'Depósito PIX', $3, 'Depósito via PIX confirmado', 'COMPLETED', $1)
         ON CONFLICT (id) DO UPDATE SET status = 'COMPLETED'`,
        [payment.id, payment.customer, payment.value]
      ).catch(e => console.warn('[WEBHOOK] DB insert ignorado:', e.message));

      console.log(`[WEBHOOK] ✅ Depósito confirmado: R$ ${payment.value} | ID: ${payment.id}`);
    } catch (e) {
      console.error('[WEBHOOK] Erro ao processar:', e.message);
    }
  }

  // Asaas espera 200 imediatamente, independente do processamento
  res.status(200).json({ received: true });
});

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '3.0.0', env: NODE_ENV, timestamp: new Date().toISOString() });
});

app.use((req, res) => res.status(404).json({ error: 'Not Found' }));

// ─── START ───────────────────────────────────────────────────────────────────
if (!DATABASE_URL) {
  console.error('[FATAL] DATABASE_URL não definida. Configure a variável de ambiente no painel do Render.');
  process.exit(1);
}

initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n💎 GoldBank API v3.0 [${NODE_ENV}] → porta ${PORT} 💎\n`);
    });
  })
  .catch(err => {
    console.error('[FATAL] Falha ao conectar no banco de dados:', err.message, err.stack);
    process.exit(1);
  });
