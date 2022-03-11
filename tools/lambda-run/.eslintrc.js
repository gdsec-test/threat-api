module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
    node: true
  },
  extends: ['eslint:recommended'],
  parserOptions: {
    ecmaVersion: 2021
  },
  plugins: ['prettier'],
  rules: {
    'prettier/prettier': [
      'error',
      { singleQuote: true, trailingComma: 'none', bracketSpacing: true }
    ],
    'max-len': ['error', { code: 120, tabWidth: 2, comments: 200 }],
    semi: ['error', 'always'],
    'space-before-function-paren': ['error', 'never'],
    'no-unused-vars': ['error'],
    quotes: ['error', 'single', { allowTemplateLiterals: true }],
    indent: ['error', 2],
    'brace-style': ['error', '1tbs', { allowSingleLine: true }],
    'object-curly-spacing': ['error', 'always'],
    curly: 'error'
  }
};
