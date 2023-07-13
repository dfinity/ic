import { Principal } from '@dfinity/principal';
import { ICHostInfoEvent } from '../../typings';
import { DBHostsItem } from './typings';
import { MalformedCanisterError } from './errors';
import logger from '../../logger';

export class ResolverMapper {
  static fromDBHostsItem(lookup: DBHostsItem): Principal | null {
    if (!lookup.canister) {
      return null;
    }

    try {
      return Principal.fromText(lookup.canister.id);
    } catch (error) {
      return null;
    }
  }

  static toDBHostsItem(lookup: Principal | null): DBHostsItem {
    if (!lookup) {
      return {
        canister: false,
      };
    }

    try {
      return {
        canister: {
          id: lookup?.toText(),
        },
      };
    } catch (error) {
      return {
        canister: false,
      };
    }
  }

  static toHTTPSUrl(url: URL): URL {
    const secureDomain = new URL(url.href);
    secureDomain.protocol = 'https:';

    return secureDomain;
  }

  static getPrincipalFromText(canisterId: string): Principal {
    try {
      return Principal.fromText(canisterId);
    } catch (err) {
      const error = err as Error;
      throw new MalformedCanisterError(error.message);
    }
  }

  static toDBHostsItemFromEvent(event: ICHostInfoEvent): DBHostsItem | null {
    try {
      return ResolverMapper.toDBHostsItem(
        ResolverMapper.getPrincipalFromText(event.canisterId)
      );
    } catch (err) {
      // logging the error in case the event had malformed values
      logger.error(err);
      return null;
    }
  }
}
