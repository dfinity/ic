import { getValueFromCookie, hashString, parseSafeInteger } from './utils';

describe('Cookie utils', () => {
  it('should get cookie value for given name', async () => {
    const cookie = '__Secure-IcGateway=ic0.app';
    const value = getValueFromCookie('__Secure-IcGateway', cookie);

    expect(value).not.toBeNull();
    expect(value).toEqual('ic0.app');
  });

  it('should get first cookie value for given name', async () => {
    const cookie =
      '__Secure-IcGateway=ic0.app; __Secure-IcCanisterId=qoctq-giaaa-aaaaa-aaaea-cai; __Secure-IcGateway=gateway.com';
    const value = getValueFromCookie('__Secure-IcGateway', cookie);

    expect(value).not.toBeNull();
    expect(value).toEqual('ic0.app');
  });

  it('should fail to get value if name is missing', async () => {
    const cookie = '__Secure-IcCanisterId=qoctq-giaaa-aaaaa-aaaea-cai';
    const value = getValueFromCookie('__Secure-IcGateway', cookie);

    expect(value).toBeNull();
  });
});

describe('Hash utils', () => {
  it('should hash string and get the expected sha-256 hex', async () => {
    const unhashed = 'my value to be hashed';
    const expectedHash =
      '9371a12e2f2a8df61ddc7e918a3d3d2805677195075e575d0ae16f4aa22f1e34';
    const hashed = await hashString(unhashed);

    expect(hashed).toEqual(expectedHash);
  });

  it('should hash string and get the expected SHA-384 hex', async () => {
    const unhashed = 'my value to be hashed';
    const expectedHash =
      '9278a649ed0cb1889814f48cea9c3d4990c292de134b0ee07432cd7242981f7f0fc3f6dda2cf55934a1987f0d8331f05';
    const hashed = await hashString(unhashed, 'SHA-384');

    expect(hashed).toEqual(expectedHash);
  });
});

describe('Number utils', () => {
  it('should return NaN for an integer overflow', async () => {
    const overflowInt = `1${Number.MAX_SAFE_INTEGER}`;
    const result = parseSafeInteger(overflowInt);

    expect(result).toBeNaN();
  });

  it('should return NaN for an invalid integer', async () => {
    const invalidInt = `unknown`;
    const result = parseSafeInteger(invalidInt);

    expect(result).toBeNaN();
  });

  it('should parse a number from a valid string with the value', async () => {
    const correctInt = `${Number.MAX_SAFE_INTEGER}`;
    const result = parseSafeInteger(correctInt);

    expect(result).toEqual(Number.MAX_SAFE_INTEGER);
  });
});
