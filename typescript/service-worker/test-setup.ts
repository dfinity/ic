// This file may be used to polyfill features that aren't available in the test
// environment.
//
// We sometimes need to do this because our target browsers are expected to have
// a feature that Node.js doesn't.

require('jest-fetch-mock').enableMocks();
global.TextEncoder = require('text-encoding').TextEncoder;
global.TextDecoder = require('text-encoding').TextDecoder;
