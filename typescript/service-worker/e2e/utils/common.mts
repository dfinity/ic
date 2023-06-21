import { setTimeout } from 'node:timers/promises';
import assert from 'node:assert';

export async function waitForServiceWorkerUpgrade(
  browser: WebdriverIO.Browser
): Promise<void> {
  await browser.refresh();
  await setTimeout(3000);
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
  assert.equal(elementText, 'This is a sample asset!');
}
