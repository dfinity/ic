import { Principal } from '@dfinity/principal';

export const DEFAULT_GATEWAY = new URL(
  self.location.protocol + '//' + 'icp-api.io'
);

export const hostnameCanisterIdMap: Map<string, Principal> = new Map(
  Object.entries({
    'identity.ic0.app': Principal.from('rdmx6-jaaaa-aaaaa-aaadq-cai'),
    'nns.ic0.app': Principal.from('qoctq-giaaa-aaaaa-aaaea-cai'),
    'dscvr.one': Principal.from('h5aet-waaaa-aaaab-qaamq-cai'),
    'dscvr.ic0.app': Principal.from('h5aet-waaaa-aaaab-qaamq-cai'),
    'personhood.ic0.app': Principal.from('g3wsl-eqaaa-aaaan-aaaaa-cai'),
  })
);
