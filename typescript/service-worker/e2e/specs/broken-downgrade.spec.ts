import {
  deployServiceWorker,
  expectSampleAssetLoaded,
  loadSampleAsset,
  runInBrowser,
  waitForServiceWorkerUpgrade,
  env,
} from '../utils';

const { baseUrl, swPath, brokenUpgradeSwPath, brokenDowngradeSwPath } = env;

async function expectSampleAssetBroken(
  contentElem: WebdriverIO.Element
): Promise<void> {
  const isDisplayed = await contentElem.isDisplayed();
  expect(isDisplayed).toBe(false);
}

it('should fail to upgrade', async () => {
  await runInBrowser(baseUrl, async (browser) => {
    let contentElem: WebdriverIO.Element;

    console.log('\n\nDeploying broken upgrade service worker...');
    await deployServiceWorker(brokenUpgradeSwPath, swPath);
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
});
