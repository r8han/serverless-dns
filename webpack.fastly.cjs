const webpack = require("webpack");

module.exports = {
  entry: "./src/server-fastly.js",
  target: ["webworker", "es2020"],
  mode: "production",
  // enable devtool in development
  // devtool: 'eval-cheap-module-source-map',

  // gist.github.com/ef4/d2cf5672a93cf241fd47c020b9b3066a
  resolve: {
    fallback: {
      // The read-only trie never invokes the builder's OS diagnostics.
      os: false,
      process: false,
      // buffer polyfill: archive.is/7OBM7
      buffer: require.resolve("buffer/"),
    },
  },

  plugins: [
    new webpack.NormalModuleReplacementPlugin(/^node:buffer$/, "buffer/"),
    new webpack.ProvidePlugin({
      Buffer: ["buffer", "Buffer"],
    }),
    new webpack.IgnorePlugin({
      resourceRegExp:
        // eslint-disable-next-line max-len
        /(^dgram$)|(^http2$)|(\/deno\/.*\.ts$)|(.*-deno\.ts$)|(.*\.deno\.ts$)|(\/node\/.*\.js$)|(.*-node\.js$)|(.*\.node\.js$)/,
    }),
    // stackoverflow.com/a/65556946
  ],

  optimization: {
    usedExports: true,
    minimize: false,
  },

  experiments: {
    outputModule: true,
  },

  // stackoverflow.com/a/68916455
  output: {
    library: {
      type: "module",
    },
    filename: "fastly.js",
    module: true,
  },
  externals: [
    ({ request }, callback) => {
      // Allow Webpack to handle fastly:* namespaced module imports by treating
      // them as modules rather than try to process them as URLs
      if (/^fastly:.*$/.test(request)) {
        return callback(null, "commonjs " + request);
      }
      callback();
    },
  ],
};
