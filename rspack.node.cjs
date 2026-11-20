const { rspack } = require("@rspack/core");

module.exports = {
  entry: "./src/server-node.js",
  target: ["node22", "es2022"],
  mode: "production",
  // The Docker image copies only node.mjs, including lazy imports.
  plugins: [new rspack.optimize.LimitChunkCountPlugin({ maxChunks: 1 })],
  optimization: {
    usedExports: true,
    minimize: false,
  },
  experiments: {
    outputModule: true,
  },
  output: {
    library: { type: "module" },
    clean: true,
    filename: "node.mjs",
    module: true,
  },
};
