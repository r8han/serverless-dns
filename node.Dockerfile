FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS setup
WORKDIR /app
COPY package.json ./
COPY scripts/audit-dependencies.sh scripts/
RUN npm install --package-lock --ignore-scripts --omit=optional && sh scripts/audit-dependencies.sh
COPY scripts/ scripts/
COPY config/blocklist-manifest.json config/
COPY src/ src/
COPY webpack.fly.cjs ./
RUN npm run build:fly && sh scripts/prepare.sh --assets

FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ENV NODE_ENV=production
WORKDIR /app
COPY --from=setup /app/dist/fly.mjs ./
COPY --from=setup /app/blocklists__ ./blocklists__/
USER node
CMD ["node", "fly.mjs"]
