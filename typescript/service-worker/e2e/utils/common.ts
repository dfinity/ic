import { setTimeout } from 'node:timers/promises';

export async function waitForServiceWorkerUpgrade(
  browser: WebdriverIO.Browser
): Promise<void> {
  await browser.refresh();
  await setTimeout(3000);
}

export async function loadSampleAssetUnderLoad(
  browser: WebdriverIO.Browser
): Promise<void> {
  await Promise.all(
    new Array(100).fill(async () => {
      const contentElem = await loadSampleAsset(browser);

      await expectSampleAssetLoaded(contentElem);
    })
  );
}

export async function loadSampleAsset(
  browser: WebdriverIO.Browser
): Promise<WebdriverIO.Element> {
  await browser.url('/sample-asset.txt');

  return await browser.$('pre');
}

export async function expectSampleAssetLoaded(
  contentElem: WebdriverIO.Element
): Promise<void> {
  await contentElem.waitForDisplayed();

  const elementText = await contentElem.getText();
  expect(elementText).toBe('This is a sample asset!');
}
