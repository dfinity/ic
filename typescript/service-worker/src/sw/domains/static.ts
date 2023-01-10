import { Principal } from '@dfinity/principal';
import { StaticDomainMappings } from './typings';

export const DEFAULT_GATEWAY = new URL(
  self.location.protocol + '//' + 'ic0.app'
);

export const hostnameCanisterIdMap: StaticDomainMappings = new Map(
  Object.entries({
    'identity.ic0.app': {
      canister: {
        principal: Principal.from('rdmx6-jaaaa-aaaaa-aaadq-cai'),
        gateway: DEFAULT_GATEWAY,
      },
    },
    'nns.ic0.app': {
      canister: {
        principal: Principal.from('qoctq-giaaa-aaaaa-aaaea-cai'),
        gateway: DEFAULT_GATEWAY,
      },
    },
    'dscvr.one': {
      canister: {
        principal: Principal.from('h5aet-waaaa-aaaab-qaamq-cai'),
        gateway: DEFAULT_GATEWAY,
      },
    },
    'dscvr.ic0.app': {
      canister: {
        principal: Principal.from('h5aet-waaaa-aaaab-qaamq-cai'),
        gateway: DEFAULT_GATEWAY,
      },
    },
    'personhood.ic0.app': {
      canister: {
        principal: Principal.from('g3wsl-eqaaa-aaaan-aaaaa-cai'),
        gateway: DEFAULT_GATEWAY,
      },
    },
  })
);
