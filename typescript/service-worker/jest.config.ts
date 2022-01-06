module.exports = {
    verbose: true,
    roots: ['src/'],
    testMatch: ['**/src/**/?(*.)+(spec|test).[jt]s?(x)'],
    setupFiles: [`<rootDir>/test-setup.ts`],
    moduleDirectories: ['node_modules'],
    collectCoverageFrom: ['**/src/sw/*.{ts,tsx}'], // TODO https://dfinity.atlassian.net/browse/L2-170: this excludes index.ts, which currently does not work due to import.meta.
    transform: {
        '^.+\\.ts$': 'ts-jest',
    },
};
