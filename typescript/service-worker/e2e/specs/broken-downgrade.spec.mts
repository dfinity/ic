import assert from 'node:assert';
import {
  deployServiceWorker,
  expectSampleAssetLoaded,
  loadSampleAsset,
  runInBrowser,
  waitForServiceWorkerUpgrade,
} from '../utils/index.mjs';

const [
  _exec,
  _file,
  baseUrl,
  swPath,
  brokenUpdateSwPath,
  brokenDowngradeSwPath,
] = process.argv;

async function expectSampleAssetBroken(
  contentElem: WebdriverIO.Element
): Promise<void> {
  const isDisplayed = await contentElem.isDisplayed();
  assert.equal(isDisplayed, false);
}

await runInBrowser(baseUrl, async (browser) => {
  let contentElem: WebdriverIO.Element;

  console.log('\n\nDeploying broken upgrade service worker...');
  await deployServiceWorker(brokenUpdateSwPath, swPath);
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetLoaded(contentElem);

  console.log('\n\nDeploying broken downgrade service worker...');
  await deployServiceWorker(brokenDowngradeSwPath, swPath);
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetBroken(contentElem);
});
