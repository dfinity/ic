import {
  deployServiceWorker,
  expectSampleAssetLoaded,
  loadSampleAsset,
  runInBrowser,
  waitForServiceWorkerUpgrade,
  env,
  loadSampleAssetUnderLoad,
} from '../utils';

const { baseUrl, swPath, currentSwPath, latestSwPath, previousSwPath } = env;

it('should load sample asset', async () => {
  await runInBrowser(baseUrl, async (browser) => {
    let contentElem: WebdriverIO.Element;

    console.log('\n\nDeploying current service worker...');
    await deployServiceWorker(currentSwPath, swPath);
    await waitForServiceWorkerUpgrade(browser);

    console.log('Running tests...');
    contentElem = await loadSampleAsset(browser);
    await expectSampleAssetLoaded(contentElem);

    console.log('\n\nDeploying latest service worker...');
    await deployServiceWorker(latestSwPath, swPath);
    await Promise.all([
      await waitForServiceWorkerUpgrade(browser),
      await loadSampleAssetUnderLoad(browser),
    ]);

    console.log('Running tests...');
    contentElem = await loadSampleAsset(browser);
    await expectSampleAssetLoaded(contentElem);

    console.log('\n\nDeploying current service worker...');
    await deployServiceWorker(currentSwPath, swPath);
    await Promise.all([
      await waitForServiceWorkerUpgrade(browser),
      await loadSampleAssetUnderLoad(browser),
    ]);

    console.log('Running tests...');
    contentElem = await loadSampleAsset(browser);
    await expectSampleAssetLoaded(contentElem);

    console.log('\n\nDeploying previous service worker...');
    await deployServiceWorker(previousSwPath, swPath);
    await Promise.all([
      await waitForServiceWorkerUpgrade(browser),
      await loadSampleAssetUnderLoad(browser),
    ]);

    console.log('Running tests...');
    contentElem = await loadSampleAsset(browser);
    await expectSampleAssetLoaded(contentElem);

    console.log('\n\nDeploying current service worker...');
    await deployServiceWorker(currentSwPath, swPath);
    await Promise.all([
      await waitForServiceWorkerUpgrade(browser),
      await loadSampleAssetUnderLoad(browser),
    ]);

    console.log('Running tests...');
    contentElem = await loadSampleAsset(browser);
    await expectSampleAssetLoaded(contentElem);
  });
});
