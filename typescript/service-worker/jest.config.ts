module.exports = {
  verbose: true,
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['src/'],
  testMatch: ['**/src/**/?(*.)+(spec|test).[jt]s?(x)'],
  setupFiles: [`<rootDir>/test-setup.ts`],
  moduleDirectories: ['node_modules'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
};
