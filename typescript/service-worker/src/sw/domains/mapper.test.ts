import { Principal } from '@dfinity/principal';
import { DBHostsItem, DomainLookup } from './typings';
import { ResolverMapper } from './mapper';
import { MalformedCanisterError, MalformedHostnameError } from './errors';

describe('Resolver mapper', () => {
  it('should map from storage host item to domain lookup', async () => {
    const item: DBHostsItem = {
      canister: {
        gateway: 'ic0.app',
        id: 'qoctq-giaaa-aaaaa-aaaea-cai',
      },
    };
    const lookup = ResolverMapper.fromDBHostsItem(item);

    expect(lookup).not.toBeNull();
    expect(lookup.canister).not.toBeFalsy();
    if (lookup.canister && item.canister) {
      expect(lookup.canister.gateway).toEqual(
        new URL(`${self.location.protocol}//${item.canister.gateway}`)
      );
      expect(lookup.canister.principal).toEqual(
        Principal.fromText(item.canister.id)
      );
    }
  });

  it('should map to web2 resource when canister not set in domain lookup', async () => {
    const lookup: DomainLookup = { canister: false };
    const item = ResolverMapper.toDBHostsItem(lookup);

    expect(item).not.toBeNull();
    expect(item.canister).toBeFalsy();
  });

  it('should map from domain lookup to storage host item', async () => {
    const lookup: DomainLookup = {
      canister: {
        gateway: new URL(`${self.location.protocol}//ic0.app`),
        principal: Principal.fromText('qoctq-giaaa-aaaaa-aaaea-cai'),
      },
    };
    const item = ResolverMapper.toDBHostsItem(lookup);

    expect(item).not.toBeNull();
    expect(item.canister).not.toBeFalsy();
    if (item.canister && lookup.canister) {
      expect(item.canister.gateway).toEqual(lookup.canister.gateway.hostname);
      expect(item.canister.id).toEqual(lookup.canister.principal.toText());
    }
  });

  it('should map to web2 resource when canister not set in host item', async () => {
    const item: DBHostsItem = { canister: false };
    const lookup = ResolverMapper.fromDBHostsItem(item);

    expect(lookup).not.toBeNull();
    expect(lookup.canister).toBeFalsy();
  });

  it('should throw error for malformed canisters', async () => {
    try {
      ResolverMapper.getPrincipalFromText('invalid-canister');
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedCanisterError);
    }
  });

  it('should throw error for malformed hostnames', async () => {
    try {
      ResolverMapper.getURLFromHostname('');
    } catch (err) {
      expect(err).toBeInstanceOf(MalformedHostnameError);
    }
  });
});
