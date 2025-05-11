/* eslint-disable import/no-extraneous-dependencies */

import { defineConfig } from 'eslint/config';

import eslintConfigs from '@dr.pogodin/eslint-configs';

export default defineConfig([
  { ignores: ['build/'] },
  eslintConfigs.configs.javascript,
  eslintConfigs.configs.typescript,
  {
    extends: [eslintConfigs.configs.jest],
    files: ['__test__/**'],
  },
]);
