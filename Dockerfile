# Etapa de build
FROM node:20 as build

WORKDIR /app

COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Etapa de produção
FROM node:20 AS production

WORKDIR /app

COPY --from=build /app/dist ./dist
COPY package*.json ./

RUN test -f .env && cp .env .env || echo ".env não encontrado, ignorando..."

COPY . .

RUN npm install --omit=dev

CMD ["node", "dist/main"]
