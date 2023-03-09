import { Principal } from '@dfinity/principal';
import { DBHostsItem } from './typings';
import { ResolverMapper } from './mapper';
import { MalformedCanisterError } from './errors';

describe('Resolver mapper', () => {
  it('should map from storage host item to domain lookup', async () => {
    const canisterId = 'qoctq-giaaa-aaaaa-aaaea-cai';
    const item: DBHostsItem = {
      canister: {
        id: canisterId,
      },
    };
    const lookup = ResolverMapper.fromDBHostsItem(item);

    expect(lookup).not.toBeNull();
    expect(lookup).not.toBeFalsy();
    expect(lookup).toEqual(Principal.fromText(canisterId));
  });

  it('should map to web2 resource when canister not set in domain lookup', async () => {
    const item = ResolverMapper.toDBHostsItem(null);

    expect(item).not.toBeNull();
    expect(item.canister).toBeFalsy();
  });

  it('should map to https: protocol in a given url that uses the http: protocol', async () => {
    const url = new URL('http://example.com');
    const secureUrl = ResolverMapper.toHTTPSUrl(url);

    expect(secureUrl.href).not.toEqual(url.href);
    expect(secureUrl.protocol).toEqual('https:');
  });

  it('should map from domain lookup to storage host item', async () => {
    const lookup = Principal.fromText('qoctq-giaaa-aaaaa-aaaea-cai');
    const item = ResolverMapper.toDBHostsItem(lookup);

    expect(item).not.toBeNull();
    expect(item.canister).not.toBeFalsy();
    expect(item.canister).toEqual({
      id: lookup.toText(),
    });
  });

  it('should map to web2 resource when canister not set in host item', async () => {
    const item: DBHostsItem = { canister: false };
    const lookup = ResolverMapper.fromDBHostsItem(item);

    expect(lookup).toBeNull();
  });

  it('should throw error for malformed canisters', async () => {
    try {
      ResolverMapper.getPrincipalFromText('invalid-canister');
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedCanisterError);
    }
  });
});
