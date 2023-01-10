export const mockLocation = (href: string): Location => {
  const url = new URL(href);

  return {
    ...url,
    protocol: url.protocol,
    hostname: url.hostname,
    host: url.host,
    href: url.href,
    hash: url.hash,
    origin: url.origin,
    port: url.port,
    search: url.search,
    pathname: url.pathname,
    ancestorOrigins: [] as unknown as DOMStringList,
    assign: jest.fn(),
    reload: jest.fn(),
    replace: jest.fn(),
  };
};
