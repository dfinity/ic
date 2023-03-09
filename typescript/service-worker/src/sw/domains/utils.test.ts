import { Principal } from '@dfinity/principal';
import {
  isRawDomain,
  maybeResolveCanisterFromHeaders,
  maybeResolveCanisterFromHostName,
  resolveCanisterFromUrl,
} from './utils';
import { mockLocation } from '../../mocks/location';

describe('Resolve canister from headers', () => {
  it('should resolve from host with canister id', async () => {
    const canisterId = 'g3wsl-eqaaa-aaaan-aaaaa-cai';
    const headers = new Headers();
    headers.set('host', `${canisterId}.ic0.app`);

    const resolve = maybeResolveCanisterFromHeaders(headers);

    expect(resolve).toEqual(Principal.fromText(canisterId));
  });

  it('should resolve removing host port', async () => {
    const canisterId = 'g3wsl-eqaaa-aaaan-aaaaa-cai';
    const headers = new Headers();
    headers.set('host', `${canisterId}.ic0.app:443`);

    const resolve = maybeResolveCanisterFromHeaders(headers);

    expect(resolve).toEqual(Principal.fromText(canisterId));
  });

  it('should return null when no canister id is found', async () => {
    const headers = new Headers();
    headers.set('host', `identity.ic0.app`);

    const resolve = maybeResolveCanisterFromHeaders(headers);

    expect(resolve).toBeNull();
  });
});

describe('Match raw url', () => {
  it('should match raw url', async () => {
    expect(isRawDomain('example.raw.ic0.app')).toBeTruthy();
    expect(isRawDomain('example.raw.ic1.app')).toBeTruthy();
    expect(isRawDomain('example.raw.ic0.dev')).toBeTruthy();
    expect(isRawDomain('example.raw.ic1.dev')).toBeTruthy();
    expect(isRawDomain('example.raw.icp0.io')).toBeTruthy();
    expect(
      isRawDomain('example.raw.some.testnet.ic1.network', false)
    ).toBeTruthy();
    expect(
      isRawDomain('example.raw.another-1.testnet.ic1.network', false)
    ).toBeTruthy();
    expect(
      isRawDomain('example.raw.another_1.testnet.ic1.network', false)
    ).toBeTruthy();
  });

  it('should not match raw url', async () => {
    expect(isRawDomain('example.raw.ic0.io')).toBeFalsy();
    expect(isRawDomain('raw.example.ic0.app')).toBeFalsy();
    expect(isRawDomain('raw.example.ic0.dev')).toBeFalsy();
    expect(isRawDomain('raw.example.icp0.io')).toBeFalsy();
    expect(isRawDomain('example.raw.icp0.app')).toBeFalsy();
    expect(isRawDomain('example.raw.icp0.dev')).toBeFalsy();
    expect(
      isRawDomain('raw.example.some.testnet.ic1.network', false)
    ).toBeFalsy();
    expect(isRawDomain('example.raw.some.testnet.network', false)).toBeFalsy();
  });
});

describe('Resolve canister from url', () => {
  it('should resolve from url with canister id', async () => {
    const canisterId = 'g3wsl-eqaaa-aaaan-aaaaa-cai';
    const url = new URL(`https://${canisterId}.ic0.app`);

    const resolve = resolveCanisterFromUrl(url);

    expect(resolve).toEqual(Principal.fromText(canisterId));
  });

  it('should return null when no canister id is found', async () => {
    const url = new URL(`https://ic0.app`);

    const resolve = resolveCanisterFromUrl(url);

    expect(resolve).toBeNull();
  });
});

describe('Resolve canister from hostname', () => {
  beforeEach(async () => {
    global.self.location = mockLocation(
      `https://g3wsl-eqaaa-aaaan-aaaaa-cai.ic0.app`
    );
  });

  it('should resolve from hostname with canister id', async () => {
    const canisterId = 'g3wsl-eqaaa-aaaan-aaaaa-cai';
    const url = new URL(`https://${canisterId}.icgateway.io`);

    const resolve = maybeResolveCanisterFromHostName(url.hostname);

    expect(resolve).not.toBeNull();
    expect(resolve).toEqual(Principal.fromText(canisterId));
  });

  it('should handle raw.ic0 as a web2 resource', async () => {
    const canisterId = 'g3wsl-eqaaa-aaaan-aaaaa-cai';
    const url = new URL(`https://${canisterId}.raw.ic0.app`);

    const resolve = maybeResolveCanisterFromHostName(url.hostname);

    expect(resolve).toBeNull();
  });

  it('should return null when no canister id is found', async () => {
    const url = new URL(`https://ic0.app`);

    const resolve = maybeResolveCanisterFromHostName(url.hostname);

    expect(resolve).toBeNull();
  });
});
