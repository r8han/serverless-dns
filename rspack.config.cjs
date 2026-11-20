const { rspack } = require("@rspack/core");

module.exports = {
  entry: "./src/server-workers.js",
  target: ["webworker", "es2022"],
  mode: "production",
  resolve: {
    fallback: {
      // The read-only trie never invokes the builder's OS diagnostics.
      os: false,
      process: false,
      buffer: require.resolve("buffer/"),
    },
  },
  plugins: [
    // Resolve node: imports through the browser fallbacks above.
    new rspack.NormalModuleReplacementPlugin(/^node:/, (resource) => {
      resource.request = resource.request.replace(/^node:/, "");
    }),
    new rspack.ProvidePlugin({
      Buffer: ["buffer", "Buffer"],
    }),
    // Keep Node-only transports out of the Worker.
    new rspack.IgnorePlugin({
      resourceRegExp:
        /(^dgram$)|(^http2$)|(\/node\/.*\.js$)|(.*-node\.js$)|(.*\.node\.js$)/,
    }),
    // The release copies only worker.js.
    new rspack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }),
  ],
  optimization: {
    usedExports: true,
    minimize: false,
  },
  experiments: {
    outputModule: true,
  },
  output: {
    library: { type: "module" },
    filename: "worker.js",
    module: true,
  },
};
