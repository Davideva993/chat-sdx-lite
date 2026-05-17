FROM node:20-alpine
WORKDIR /app
COPY back/package*.json ./
RUN npm ci --omit=dev
COPY back/ .
EXPOSE 3006
CMD ["node", "server.js"]
