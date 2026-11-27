FROM node:26-alpine AS webbuild
WORKDIR /app
COPY package*.json ./
COPY web/package.json web/
RUN npm ci -w web
COPY web/ web/
RUN npm run build -w web

FROM node:26-alpine
WORKDIR /app
COPY package*.json ./
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci --omit=dev
COPY server/ server/
COPY data/ data/
COPY --from=webbuild /app/web/dist web/dist/
ENV PORT=7818 HOST=0.0.0.0 TI_IN_DOCKER=1 NODE_ENV=production
EXPOSE 7818
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD node -e "fetch('http://127.0.0.1:7818/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/src/index.js"]
