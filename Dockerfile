FROM node:20-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY serve.js ./
COPY templates/ ./templates/

EXPOSE 8082

CMD ["node", "serve.js"]
