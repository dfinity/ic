import { browser, $ } from '@wdio/globals';

describe('Asset loading', () => {
  it('should load the sample asset', async () => {
    await browser.url('/sample-asset.txt');

    const contentElem = await $('pre');
    await contentElem.waitForDisplayed();

    await expect(contentElem).toHaveText('This is a sample asset!');
  });
});
