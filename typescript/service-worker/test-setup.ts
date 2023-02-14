// This file may be used to polyfill features that aren't available in the test
// environment.
//
// We sometimes need to do this because our target browsers are expected to have
// a feature that Node.js doesn't.
import { mockBrowserCacheAPI } from './src/mocks/browser-cache';

global.TextEncoder = require('text-encoding').TextEncoder;
global.TextDecoder = require('text-encoding').TextDecoder;
Object.defineProperty(self, 'location', {
  value: {
    protocol: 'https:',
    host: 'rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app',
    origin: 'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app',
    hostname: 'rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app',
    toString: () => 'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app',
    href: 'https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app',
  },
  writable: true,
});
process.env.FORCE_FETCH_ROOT_KEY = 'true';
Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: require('crypto').webcrypto.subtle,
  },
});

require('jest-fetch-mock').enableMocks();

Object.defineProperty(global.self, 'caches', {
  value: mockBrowserCacheAPI(),
  writable: true,
});
