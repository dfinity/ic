import { Principal } from '@dfinity/principal';
import { ICHostInfoEvent } from '../../typings';
import { DBHostsItem, DomainLookup } from './typings';
import { MalformedCanisterError, MalformedHostnameError } from './errors';

export class ResolverMapper {
  static fromDBHostsItem(
    lookup: DBHostsItem,
    protocol = self.location.protocol
  ): DomainLookup {
    if (!lookup.canister) {
      return { canister: false };
    }

    return {
      canister: {
        principal: Principal.fromText(lookup.canister.id),
        gateway: new URL(protocol + '//' + lookup.canister.gateway),
      },
    };
  }

  static toDBHostsItem(lookup: DomainLookup): DBHostsItem {
    if (!lookup.canister) {
      return { canister: false };
    }

    return {
      canister: {
        id: lookup.canister.principal.toText(),
        gateway: lookup.canister.gateway.hostname,
      },
    };
  }

  static getPrincipalFromText(canisterId: string): Principal {
    try {
      return Principal.fromText(canisterId);
    } catch (err) {
      const error: Error = err;
      throw new MalformedCanisterError(error.message);
    }
  }

  static getURLFromHostname(
    hostname: string,
    protocol = self.location.protocol
  ): URL {
    try {
      return new URL(protocol + '//' + hostname);
    } catch (err) {
      const error: Error = err;
      throw new MalformedHostnameError(error.message);
    }
  }

  static toDBHostsItemFromEvent(event: ICHostInfoEvent): DBHostsItem | null {
    try {
      return ResolverMapper.toDBHostsItem({
        canister: {
          gateway: ResolverMapper.getURLFromHostname(event.gateway),
          principal: ResolverMapper.getPrincipalFromText(event.canisterId),
        },
      });
    } catch (err) {
      // logging the error in case the event had malformatted values
      console.error(err);
      return null;
    }
  }
}
