# Deploy no Render — server-goldbank (modo DEMO)

Serviço: **https://server-goldbank.onrender.com**  
Repo: **https://github.com/amos-fernandes/server-goldbank**

## ⚠️ Restaurar serve.js (obrigatório uma vez)

Um commit intermediário corrompeu `serve.js`. Restaure o arquivo bom e aplique o DEMO_MODE:

```bash
git clone https://github.com/amos-fernandes/server-goldbank.git
cd server-goldbank

# Restaura serve.js da versão boa (antes do placeholder)
git show 0905081a07fb3031ae86e138e922638c59f4b437:serve.js > serve.js

# Aplique o patch DEMO_MODE (bloco abaixo) ou peça ao Grok o arquivo completo
# Depois:
git add serve.js package.json RENDER.md .env.private.example
git commit -m "restore serve.js + DEMO_MODE"
git push origin main
```

### Patch mínimo DEMO_MODE (colar no serve.js)

**1) No `process.env` destructuring, adicione `DEMO_MODE` e logo abaixo:**

```js
  DEMO_MODE,
} = process.env;

const IS_DEMO_MODE = String(DEMO_MODE || '').toLowerCase() === 'true'
  || String(DEMO_MODE || '') === '1'
  || (!process.env.NECTA_API_KEY && !process.env.AZIFY_API_KEY);
if (IS_DEMO_MODE) {
  console.log('[MODE] DEMO_MODE ativo — Necta/Azify desligados; conta demo e PIX mock');
}
```

**2) No início de cada método do `PixProvider`, adicione early-return se `IS_DEMO_MODE`:**

- `createPixDeposit` → retorna QR/link mock `provider: 'demo'`
- `createPixTransfer` → `{ success:true, provider:'demo', status:'COMPLETED' }`
- `getAccountBalance` → `{ balance: 12500.50, availableBalance: 12500.50 }`
- `getTransactions` → lista mock de 2 lançamentos
- `createCustomer` → customer local `cus_local_*`
- `getKycStatus` → `{ status: 'APPROVED' }`

A conta **demo@aibank.com.br** já existia no código (login sem validar senha).

## Configurar o Render

1. Serviço Web **server-goldbank**
2. Build: `npm install` · Start: `npm start` · Branch: `main`
3. **Environment:**

| Key | Value |
|-----|--------|
| `DEMO_MODE` | `true` |
| `NODE_ENV` | `production` |
| `PORT` | `8082` |
| `JWT_SECRET` | *(hex longo)* |
| `ENCRYPTION_KEY` | *(64 hex chars)* |
| `ALLOWED_ORIGINS` | `https://server-goldbank.onrender.com,exp://localhost:8081,http://localhost:8081,http://localhost:19006` |

**Remova** `NECTA_*` e `AZIFY_*` (ou deixe vazias).

Gere secrets:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

4. **Manual Deploy** após o push do `serve.js` restaurado.

## Conta demo

| Campo | Valor |
|-------|--------|
| Email | `demo@aibank.com.br` |
| Senha | qualquer |

## App mobile

```env
EXPO_PUBLIC_API_URL=https://server-goldbank.onrender.com
```

## Health

```bash
curl -s https://server-goldbank.onrender.com/health
# Logs devem mostrar: [MODE] DEMO_MODE ativo
```

## Voltar Necta/Azify

1. Preencher `NECTA_*` / `AZIFY_*`
2. `DEMO_MODE=false`
3. Redeploy
