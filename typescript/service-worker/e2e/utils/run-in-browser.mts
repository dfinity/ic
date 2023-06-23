import { remote } from 'webdriverio';
import { ChromeOptions } from '@wdio/types/build/Capabilities';

export interface RunConfig {
  currentSwPath: string;
  latestSwPath: string;
  previousSwPath: string;
  swPath: string;
}

export async function runInBrowser(
  baseUrl: string,
  test: (browser: WebdriverIO.Browser) => Promise<void>
): Promise<void> {
  const chromeOptions: ChromeOptions = { args: [] };

  console.log('Getting remote browser...');
  const browser = await remote({
    capabilities: {
      browserName: 'chrome',
      'goog:chromeOptions': chromeOptions,
    },
    automationProtocol: 'webdriver',
    path: '/wd/hub',
    logLevel: 'info',
    outputDir: './',
    baseUrl,
  });

  try {
    await test(browser);
  } catch (e) {
    console.error('Error occurred during test', e);

    throw e;
  } finally {
    try {
      console.log('Performing session cleanup...');
      await browser.deleteSession();
    } catch (e) {
      console.error('Error occurred during session cleanup', e);
    }
  }
}
