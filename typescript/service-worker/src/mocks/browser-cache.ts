import CacheMock from 'browser-cache-mock';

export const mockBrowserCacheAPI = (): CacheStorage => {
  const cacheMock = new CacheMock();
  return {
    open: async () => cacheMock,
    ...cacheMock,
  } as unknown as CacheStorage;
};
