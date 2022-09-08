module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
    node: true
  },
  extends: ['eslint:recommended', 'plugin:mocha/recommended'],
  parserOptions: {
    ecmaVersion: 2021
  },
  globals: {
    sandbox: 'writable'
  },
  plugins: ['prettier', 'mocha'],
  rules: {
    'prettier/prettier': [
      'warn',
      { singleQuote: true, trailingComma: 'none', bracketSpacing: true }
    ],
    'max-len': ['error', { code: 120, tabWidth: 2, comments: 200 }],
    semi: ['error', 'always'],
    'space-before-function-paren': 'off',
    'no-unused-vars': ['warn'],
    quotes: ['error', 'single', { allowTemplateLiterals: true }],
    indent: ['error', 2],
    'brace-style': ['error', '1tbs', { allowSingleLine: true }],
    'object-curly-spacing': ['error', 'always'],
    curly: 'error',
    'mocha/no-mocha-arrows': 'off',
    'no-multiple-empty-lines': ['error', { max: 2 }]
  }
};
