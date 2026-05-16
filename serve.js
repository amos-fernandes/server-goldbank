const http = require('http');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '.env.private' });

const {
  ASAAS_API_KEY,
  ASAAS_BASE_URL,
  ASAAS_WALLET_ID,
  ENCRYPTION_KEY,
  PORT = 8082
} = process.env;

const DB_PATH = path.join(__dirname, 'db.json');

function loadDb() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    }
  } catch (e) {
    console.error('[DB] Erro ao ler db.json:', e.message);
  }
  return { users: [], transactions: [] };
}

function saveDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

let db = loadDb();

const asaas = axios.create({
  baseURL: ASAAS_BASE_URL,
  headers: {
    'access_token': ASAAS_API_KEY,
    'Content-Type': 'application/json'
  }
});

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  console.log(`[REQ] ${req.method} ${pathname}`);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', async () => {
    try {
      if (pathname === '/api/auth/register') {
        const payload = JSON.parse(body);
        console.log('[ASAAS] Registrando:', payload.email);

        try {
          const asaasCustomer = await asaas.post('/customers', {
            name: payload.name,
            email: payload.email,
            cpfCnpj: payload.cpfCnpj,
            mobilePhone: payload.phone,
            notificationDisabled: true
          });

          const newUser = {
            id: asaasCustomer.data.id,
            name: payload.name,
            email: payload.email,
            asaasStatus: 'ACTIVE',
            walletId: ASAAS_WALLET_ID,
            token: crypto.randomBytes(32).toString('hex')
          };

          db = loadDb();
          db.users.push(newUser);
          saveDb(db);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(newUser));
        } catch (err) {
          console.error('[ASAAS ERROR]', err.response?.data || err.message);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.response?.data?.errors?.[0]?.description || 'Erro no Asaas' }));
        }
      }
      else if (pathname === '/api/auth/login') {
        const payload = JSON.parse(body);
        db = loadDb();
        const user = db.users.find(u => u.email === payload.email.toLowerCase());

        if (!user) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Conta não encontrada. Você já se registrou? O servidor pode ter reiniciado — faça um novo registro.' }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(user));
      }
      else if (pathname === '/api/auth/me') {
        const auth = req.headers.authorization;
        if (!auth) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Token não fornecido' }));
          return;
        }
        const token = auth.replace('Bearer ', '');
        db = loadDb();
        const user = db.users.find(u => u.token === token);
        if (!user) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Sessão expirada' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(user));
      }
      else if (pathname === '/api/pix/deposit') {
        const payload = JSON.parse(body);
        const customerId = payload.customerId;

        if (!customerId || !customerId.startsWith('cus_')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'ID de cliente inválido. Crie uma conta nova via REGISTRO para gerar um ID real no Asaas.' }));
          return;
        }

        console.log('[PIX] Solicitando:', payload.amount, 'para cliente:', customerId);

        try {
          const payment = await asaas.post('/payments', {
            customer: customerId,
            billingType: 'PIX',
            value: payload.amount,
            dueDate: new Date(Date.now() + 86400000).toISOString().split('T')[0],
            description: payload.description || 'Depósito GoldBank'
          });

          const qrCode = await asaas.get(`/payments/${payment.data.id}/pixQrCode`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            qrCodeBase64: qrCode.data.encodedImage,
            qrCodePayload: qrCode.data.payload,
            value: payment.data.value,
            chargeId: payment.data.id
          }));
        } catch (err) {
          console.error('[PIX ERROR]', err.response?.data || err.message);
          
          // Fallback para Mock se o PIX não estiver ativo na conta Asaas (para testes de UI)
          if (err.response?.data?.errors?.[0]?.code === 'invalid_billingType' || err.message.includes('404')) {
            console.log('[PIX] Usando Fallback MOCK para teste de interface.');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              qrCodeBase64: 'iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAAB7yyAtAAAABlBMVEX///8AAABVwtN+AAAAAXRSTlMAQObYZgAAAAlwSFlzAAAOxAAADsQBlSsOGwAAADZJREFUeF7twTEBAAAAwqD1T20LL6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOBj0AAAB0SFAAAAAAElFTkSuQmCC', // Pequeno placeholder base64
              qrCodePayload: '00020101021226840014br.gov.bcb.pix25620014br.gov.bcb.pix0136goldbank-mock-payload-for-testing-only5204000053039865405' + payload.amount.toFixed(2) + '5802BR5915GOLD BANK MOCK6008SAO PAULO62070503***6304ABCD',
              value: payload.amount,
              chargeId: 'pay_mock_' + Date.now()
            }));
            return;
          }

          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: err.response?.data?.errors?.[0]?.description || 'Erro ao gerar PIX no Asaas'
          }));
        }
      }
      else if (pathname === '/api/wallet/transactions') {
        db = loadDb();
        const auth = req.headers.authorization;
        const token = auth ? auth.replace('Bearer ', '') : null;
        const user = token ? db.users.find(u => u.token === token) : null;

        if (!user || !user.id.startsWith('cus_')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([]));
          return;
        }

        try {
          const { data } = await asaas.get('/payments', {
            params: { customer: user.id, limit: 20 }
          });

          const txs = data.data.map(p => ({
            id: p.id,
            type: 'INFLOW',
            category: 'Depósito PIX',
            amount: p.value,
            description: p.description || 'Depósito',
            date: p.dateCreated,
            status: p.status === 'RECEIVED' || p.status === 'CONFIRMED' ? 'COMPLETED' : 'PENDING'
          }));

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(txs));
        } catch (err) {
          console.error('[TX ERROR]', err.response?.data || err.message);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([]));
        }
      }
      else if (pathname === '/api/wallet/balance') {
        db = loadDb();
        const auth = req.headers.authorization;
        const token = auth ? auth.replace('Bearer ', '') : null;
        const user = token ? db.users.find(u => u.token === token) : null;

        try {
          const wallet = await asaas.get(`/wallets/${ASAAS_WALLET_ID}/balance`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            balance: wallet.data.balance ?? 0,
            availableBalance: wallet.data.availableBalance ?? 0,
            totalTransferValue: 0,
            isDemo: false,
            message: user?.asaasStatus === 'ACTIVE' ? null : 'Conta pendente de ativação.'
          }));
        } catch (err) {
          console.error('[BALANCE ERROR]', err.response?.data || err.message);
          
          // Fallback para Mock se a Wallet não for encontrada ou API falhar
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            balance: 1250.75, // Valor mock para teste
            availableBalance: 1200.00,
            totalTransferValue: 500.00,
            isDemo: true,
            message: 'Saldo demonstrativo (Asaas em análise ou Wallet ID inválido).'
          }));
        }
      }
      else if (pathname === '/api/dashboard/summary') {
        try {
          const wallet = await asaas.get(`/wallets/${ASAAS_WALLET_ID}/balance`);
          const balance = wallet.data.balance ?? 0;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            totalBalanceBRL: balance,
            bankBalanceBRL: balance,
            cryptoBalanceBRL: 0,
            accountsCount: 1,
            monthlyInflow: 0,
            monthlyOutflow: 0
          }));
        } catch (err) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            totalBalanceBRL: 0,
            bankBalanceBRL: 0,
            cryptoBalanceBRL: 0,
            accountsCount: 1,
            monthlyInflow: 0,
            monthlyOutflow: 0
          }));
        }
      }
      else if (pathname === '/api/crypto/mb/prices') {
        try {
          const { data } = await axios.get('https://api.mercadobitcoin.net/api/v4/tickers', {
            params: { symbols: ['BTC-BRL', 'ETH-BRL', 'SOL-BRL', 'XRP-BRL', 'BNB-BRL', 'ADA-BRL', 'USDT-BRL'] }
          });
          const prices = data.map(t => ({
            coin: t.pair.split('-')[0],
            last: parseFloat(t.last),
            open: parseFloat(t.open)
          }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(prices));
        } catch (err) {
          console.error('[MB ERROR]', err.message);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([]));
        }
      }
      else if (pathname === '/api/crypto/binance/prices') {
        try {
          const symbols = ['BTCUSDT', 'ETHUSDT', 'SOLUSDT', 'XRPUSDT', 'BNBUSDT', 'ADAUSDT'];
          const { data } = await axios.get('https://api.binance.com/api/v3/ticker/price', {
            params: { symbols: JSON.stringify(symbols) }
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(data.map(p => ({ symbol: p.symbol, price: parseFloat(p.price) }))));
        } catch (err) {
          console.error('[BINANCE ERROR]', err.message);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([]));
        }
      }
      else if (pathname === '/api/crypto/buy') {
        const payload = JSON.parse(body);
        console.log('[CRYPTO] Compra solicitada:', payload);
        
        // Mock simple: assume BTC is 350k, ETH 15k, others 1k for estimation if prices fetch fails
        let price = 1000;
        if (payload.coin === 'BTC') price = 350000;
        else if (payload.coin === 'ETH') price = 15000;

        const estimatedAmount = payload.amountBRL / price;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          success: true, 
          estimatedCoinAmount: estimatedAmount,
          coin: payload.coin,
          amountBRL: payload.amountBRL,
          message: `Compra de ${payload.coin} realizada com sucesso.` 
        }));
      }
      else if (pathname === '/api/user/mb-credentials') {
        const payload = JSON.parse(body);
        db = loadDb();
        const auth = req.headers.authorization;
        const token = auth ? auth.replace('Bearer ', '') : null;
        const idx = token ? db.users.findIndex(u => u.token === token) : -1;

        if (idx === -1) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Não autorizado' }));
          return;
        }

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
        let encrypted = cipher.update(JSON.stringify(payload), 'utf-8', 'hex');
        encrypted += cipher.final('hex');

        db.users[idx].mbCredentials = {
          data: encrypted,
          iv: iv.toString('hex')
        };
        saveDb(db);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      }
      else if (pathname === '/api/user/kyc') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: 'Documentos recebidos para análise.' }));
      }
      else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not Found' }));
      }
    } catch (e) {
      console.error('[SERVER ERR]', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Error' }));
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`💎 Backend ASAAS Ativo na porta ${PORT} 💎`);
});
