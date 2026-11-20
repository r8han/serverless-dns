FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS setup
WORKDIR /app
COPY scripts/ scripts/
COPY src/ src/
COPY config/blocklist-manifest.json config/
COPY .node-version package.json package-lock.json ./
# The pinned bootstrap image only installs the verified Node 26 executable.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/node26/bin \
    && node scripts/runtime-binary.mjs node /opt/node26/bin \
    && /opt/node26/bin/node --version
ENV PATH="/opt/node26/bin:${PATH}"
RUN node scripts/runtime-binary.mjs bun && npm ci --ignore-scripts --omit=optional && sh scripts/audit-dependencies.sh
RUN bun run build:bun && sh scripts/prepare.sh --assets

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
ENV NODE_ENV=production BUN_ENV=production
WORKDIR /app
COPY --from=setup /usr/local/bin/bun /usr/local/bin/bun
COPY --from=setup /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=setup /app/dist/bun.mjs ./
COPY --from=setup /app/blocklists__ ./blocklists__/
USER 65532:65532
CMD ["bun", "run", "./bun.mjs"]
