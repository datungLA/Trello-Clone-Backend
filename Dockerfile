FROM node:24-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --chown=node:node src ./src
COPY --chown=node:node migrations ./migrations
COPY --chown=node:node test ./test
RUN mkdir -p /app/dev-mail && chown node:node /app/dev-mail
USER node
EXPOSE 3000
CMD ["node", "src/server.js"]
