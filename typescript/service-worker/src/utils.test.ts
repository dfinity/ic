import { getValueFromCookie } from './utils';

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
