# Deploy no Render — server-goldbank (modo DEMO)

Serviço atual: **https://server-goldbank.onrender.com**  
Repo: **https://github.com/amos-fernandes/server-goldbank**

## Objetivo temporário

- **Sem** Necta e **sem** Azify  
- Conta **demo** + demais rotas (auth, wallet mock, GTK se configurado, crypto prices, etc.)

## 1. No painel Render

1. Abra o serviço **server-goldbank** (Web Service).
2. **Settings → Build & Deploy**
   - Repository: `amos-fernandes/server-goldbank`
   - Branch: `main`
   - Runtime: Node
   - Build Command: `npm install`
   - Start Command: `npm start`
   - (Se usar Docker) Dockerfile na raiz já existe.
3. **Environment** → adicione:

| Key | Value |
|-----|--------|
| `DEMO_MODE` | `true` |
| `NODE_ENV` | `production` |
| `PORT` | `8082` |
| `JWT_SECRET` | *(hex 64+ chars — gere um novo)* |
| `ENCRYPTION_KEY` | *(hex 64 chars)* |
| `ALLOWED_ORIGINS` | `https://server-goldbank.onrender.com,exp://localhost:8081,http://localhost:8081,http://localhost:19006` |
| `GTK_API_URL` | `https://gtk-api-529742420922.southamerica-east1.run.app` *(opcional)* |
| `GTK_API_KEY` | *(opcional)* |

**Remova ou deixe vazias:** `NECTA_*`, `AZIFY_*`.

4. **Manual Deploy** → Deploy latest commit.

Gerar secrets:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## 2. Conta demo

| Campo | Valor |
|-------|--------|
| Email | `demo@aibank.com.br` |
| Senha | qualquer (login demo não valida senha) |
| User id | `cus_demo_001` |

No app mobile, login com esse e-mail.  
Header opcional: `x-demo-mode: true` em algumas rotas de preço.

## 3. App mobile (`aibank-mobile`)

No `.env`:
```env
EXPO_PUBLIC_API_URL=https://server-goldbank.onrender.com
```

## 4. Health check

```bash
curl https://server-goldbank.onrender.com/health
# ou
curl https://server-goldbank.onrender.com/api/health
```

Logs no Render devem mostrar:
```
[MODE] DEMO_MODE ativo — Necta/Azify desligados; conta demo e PIX mock
```

## 5. Voltar Necta/Azify depois

1. Preencher `NECTA_*` / `AZIFY_*` no Environment.
2. `DEMO_MODE=false` (ou remover).
3. Redeploy.

## Observações

- Sem `DATABASE_URL` o server usa memória (usuários registrados somem no restart — ok para demo).
- Free tier Render pode dormir; primeiro request pode demorar ~30s.
- Não commite `.env.private` com secrets reais.
