module.exports = {
  verbose: true,
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['src/'],
  testMatch: ['**/src/**/?(*.)+(spec|test).[jt]s?(x)'],
  setupFiles: ['<rootDir>/test-setup.ts', 'fake-indexeddb/auto'],
  moduleDirectories: ['node_modules'],
  moduleFileExtensions: ['js', 'ts', 'html'],
  moduleNameMapper: {
    '^html-loader.+!(.*)$': '$1',
  },
  transform: {
    '^.+\\.html$': '<rootDir>/test/html-loader.js',
    '^.+\\.[tj]s$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }],
  },
  reporters: ['default', 'jest-junit'],
};
