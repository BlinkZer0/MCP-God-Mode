module.exports = {
  root: true,
  extends: ['eslint:recommended', 'semistandard'],
  parserOptions: {
    ecmaVersion: 2017
  },
  env: {
    browser: true,
    mocha: true,
    node: true
  },
  globals: {
    Promise: true
  },
  rules: {
    'space-before-function-paren': ['error', 'always'],
    'no-unused-vars': [
      'error',
      {
        args: 'none'
      }
    ],
    semi: 'error'
  }
};
