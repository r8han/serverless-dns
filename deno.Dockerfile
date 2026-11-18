FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS setup
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --omit=optional
COPY scripts/ scripts/
COPY config/blocklist-manifest.json config/
COPY src/ src/
COPY deno.lock import_map.json LICENSE ./
RUN node scripts/runtime-binary.mjs deno && sh scripts/prepare.sh --assets && node scripts/stage-deno.mjs release && cd release && deno cache --no-remote --no-npm --frozen src/server-deno.ts

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ENV DENO_DIR=/tmp/deno-cache DENO_ENV_DOMAIN=production DENO_NO_UPDATE_CHECK=1
WORKDIR /app
COPY --from=setup /usr/local/bin/deno /usr/local/bin/deno
COPY --from=setup /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=setup /app/release/ ./
COPY --from=setup /app/blocklists__ ./blocklists__/
USER 65532:65532
CMD ["deno", "run", "--frozen", "--no-remote", "--no-npm", "--allow-env", "--allow-net", "--allow-read=/app,/run/secrets", "src/server-deno.ts"]
