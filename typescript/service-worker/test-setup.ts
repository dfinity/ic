// This file may be used to polyfill features that aren't available in the test
// environment.
//
// We sometimes need to do this because our target browsers are expected to have
// a feature that Node.js doesn't.
import { mockBrowserCacheAPI } from './src/mocks/browser-cache';
import path from 'path';
import fs from 'fs';
import { Crypto } from '@peculiar/webcrypto';

const webcrypto = new Crypto();

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

// web crypto mock implementation for tests

const getRandomValuesMockFn = (array: ArrayBufferView) => {
  const view = new Uint8Array(
    array.buffer,
    array.byteOffset,
    array.byteLength
  );
  for (let i = 0; i < view.length; i++) {
    view[i] = Math.floor(Math.random() * 256);
  }
  return array;
};

Object.defineProperty(global.window, 'crypto', {
  value: {
    subtle: webcrypto.subtle,
    getRandomValues: getRandomValuesMockFn,
  },
});

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: webcrypto.subtle,
    getRandomValues: getRandomValuesMockFn,
  },
});

require('jest-fetch-mock').enableMocks();

Object.defineProperty(global.self, 'caches', {
  value: mockBrowserCacheAPI(),
  writable: true,
});

jest.mock('@dfinity/response-verification/dist/web/web_bg.wasm', () => {
  const wasmFilePath = path.resolve(
    __dirname,
    'node_modules/@dfinity/response-verification/dist/web/web_bg.wasm'
  );
  const wasmBinary = fs.readFileSync(wasmFilePath);
  const base64WasmBinary = Buffer.from(wasmBinary).toString('base64');

  return `module.exports = '${base64WasmBinary}'`;
});
