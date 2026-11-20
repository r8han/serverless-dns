import google from "eslint-config-google";
import prettier from "eslint-plugin-prettier";
import globals from "globals";

// ESLint removed these two rules. This repo already had both disabled.
const googleRules = { ...google.rules };
delete googleRules["require-jsdoc"];
delete googleRules["valid-jsdoc"];

export default [
  {
    ignores: [
      "dist/",
      "worker/",
      "pkg/",
      "test/data/cache/",
      "src/core/cfg.js",
    ],
  },
  {
    languageOptions: {
      globals: { ...globals.node, ...globals.worker },
    },
    plugins: { prettier },
    rules: {
      ...googleRules,
      // Google JS rules, missing in "eslint-config-google" package
      "eqeqeq": ["error", "smart"],

      // Rules disabled to avoid conflicts with prettier
      // See: https://github.com/prettier/eslint-config-prettier
      "indent": 0,
      "object-curly-spacing": 0,
      "operator-linebreak": 0,
      "space-before-function-paren": 0,

      // Our rules overrides.
      "comma-dangle": 0,
      "quotes": ["error", "double", { allowTemplateLiterals: true }],
      "no-unused-vars": "warn",
      "new-cap": ["error", { properties: false }],
      "max-len": [
        "error",
        {
          code: 120,
          ignoreComments: true,
          ignoreUrls: true,
          ignoreStrings: true,
          ignoreTemplateLiterals: true,
        },
      ],
      "generator-star-spacing": [
        "error",
        {
          before: false,
          after: true, // function* () {}
          anonymous: "neither", // function*() {}
          method: { before: false, after: false }, // { *gen() {} }
        },
      ],

      // Enforces rules from .prettierrc file.
      // These should be fixed automatically with formatting.
      // See: https://github.com/prettier/eslint-plugin-prettier
      "prettier/prettier": "error",
    },
  },
];
