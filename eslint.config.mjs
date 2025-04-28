/* eslint-disable import/no-extraneous-dependencies */

import { defineConfig } from 'eslint/config';
import globals from 'globals';

import eslintConfigs from '@dr.pogodin/eslint-configs';

export default defineConfig([
  {
    languageOptions: {
      globals: globals.node,
      parserOptions: {
        requireConfigFile: false,
      },
    },
  },
  {
    extends: [eslintConfigs.configs.javascript],
    rules: {
      // TODO: Perhaps, we should upgrade library code to use Babel,
      // ES6 features and modules, etc. For now these related rules
      // are turned off.
      'import/no-commonjs': 'off',
    },
  },
  {
    files: ['test/**'],
    languageOptions: {
      globals: globals.mocha,
    },
    rules: {
      'import/no-extraneous-dependencies': ['error', {
        devDependencies: true,
      }],
    },
  },
]);
