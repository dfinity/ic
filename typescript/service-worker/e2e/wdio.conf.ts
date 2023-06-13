import type { Options } from '@wdio/types';

export const config: Options.Testrunner = {
  runner: 'local',
  autoCompileOpts: {
    autoCompile: true,
    tsNodeOpts: {
      project: './tsconfig.json',
      transpileOnly: true,
    },
  },
  specs: ['./specs/**/*'],
  exclude: [],
  maxInstances: 10,
  automationProtocol: 'webdriver',
  path: '/wd/hub',
  capabilities: [
    {
      browserName: 'chrome',
      'goog:chromeOptions': {
        args: [],
      },
    },
  ],
  logLevel: 'info',
  bail: 0,
  waitforTimeout: 10000,
  connectionRetryTimeout: 120000,
  connectionRetryCount: 3,
  framework: 'jasmine',
  reporters: ['spec'],
  jasmineOpts: {
    defaultTimeoutInterval: 60000,
  },
};
