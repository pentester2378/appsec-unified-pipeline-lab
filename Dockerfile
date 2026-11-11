FROM node:22-alpine
WORKDIR /opt/app

# First PoC: npm install is used because a real registry-resolved lockfile
# cannot be bundled without downloading dependencies. Generate and commit
# package-lock.json, then switch to `npm ci --omit=dev` for enterprise use.
COPY package*.json ./
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev --ignore-scripts --no-audit --no-fund; \
    else \
      npm install --omit=dev --ignore-scripts --no-audit --no-fund; \
    fi
COPY --chown=node:node src/ ./src/
USER node
EXPOSE 3000
CMD ["node", "src/server.js"]
