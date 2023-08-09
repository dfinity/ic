import 'web-streams-polyfill';
import 'compression-streams-polyfill';

// This file may be used to polyfill features that aren't available in the test
// environment.
//
// We sometimes need to do this because our target browsers are expected to have
// a feature that Node.js doesn't.
import { mockBrowserCacheAPI } from './src/mocks/browser-cache';

if (!process.env.DEBUG_LOGS) {
  jest.mock('./src/logger');
}

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
const crypto = require('crypto');
Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: require('crypto').webcrypto.subtle,
    getRandomValues: (arr: any[]) => crypto.randomBytes(arr.length),
  },
});

require('jest-fetch-mock').enableMocks();
// Allow for fetch() mock to handle streams
// https://github.com/jefflau/jest-fetch-mock/issues/113#issuecomment-1418504168
import { Readable } from 'stream';
class TempResponse extends Response {
  constructor(...args: any[]) {
    if (args[0] instanceof ReadableStream) {
      args[0] = Readable.from(args[0] as any);
    }
    super(...args);
  }
}
Object.defineProperty(global, 'Response', {
  value: TempResponse,
});

Object.defineProperty(global.self, 'caches', {
  value: mockBrowserCacheAPI(),
  writable: true,
});
