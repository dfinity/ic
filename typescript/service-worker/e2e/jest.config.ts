import type { JestConfigWithTsJest } from 'ts-jest';

const config: JestConfigWithTsJest = {
  preset: 'ts-jest/presets/default-esm',
  setupFiles: ['dotenv/config'],
  rootDir: '.',
  testTimeout: 30_000,
};

export default config;
