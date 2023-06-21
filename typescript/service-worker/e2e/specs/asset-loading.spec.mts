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
  currentSwPath,
  latestSwPath,
  previousSwPath,
] = process.argv;

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
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetLoaded(contentElem);

  console.log('\n\nDeploying current service worker...');
  await deployServiceWorker(currentSwPath, swPath);
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetLoaded(contentElem);

  console.log('\n\nDeploying previous service worker...');
  await deployServiceWorker(previousSwPath, swPath);
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetLoaded(contentElem);

  console.log('\n\nDeploying current service worker...');
  await deployServiceWorker(currentSwPath, swPath);
  await waitForServiceWorkerUpgrade(browser);

  console.log('Running tests...');
  contentElem = await loadSampleAsset(browser);
  await expectSampleAssetLoaded(contentElem);
});
