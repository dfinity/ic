use crate::{
    address_management,
    address_management::{get_btc_ecdsa_public_key, get_main_address},
    canister_common::BitcoinCanister,
    upgrade_management, utxo_management, AddAddressWithParametersError, AddressNotTracked,
    AddressType, BalanceUpdate, BitcoinAgentState, DerivationPathTooLong, EcdsaPubKey,
    MinConfirmationsTooHigh, Satoshi, Utxo, UtxosState, UtxosUpdate, STABILITY_THRESHOLD,
};
use bitcoin::Address;
use std::{collections::HashMap, error::Error};
#[cfg(test)]
use {
    crate::{canister_mock::BitcoinCanisterMock, types::from_bitcoin_network_to_types_network},
    bitcoin::Network,
};

#[derive(Clone)]
pub struct BitcoinAgent<C: BitcoinCanister> {
    pub(crate) bitcoin_canister: C,
    pub(crate) main_address_type: AddressType,
    pub(crate) ecdsa_pub_key_addresses: HashMap<Address, EcdsaPubKey>,
    pub(crate) utxos_state_addresses: HashMap<Address, UtxosState>,
}

impl<C: BitcoinCanister> BitcoinAgent<C> {
    /// Creates a new Bitcoin agent using the given Bitcoin canister.
    pub fn new(
        bitcoin_canister: C,
        main_address_type: &AddressType,
        min_confirmations: u32,
    ) -> Result<Self, MinConfirmationsTooHigh> {
        if min_confirmations > STABILITY_THRESHOLD {
            return Err(MinConfirmationsTooHigh);
        }
        let main_address = get_main_address(&bitcoin_canister.get_network(), main_address_type);
        // TODO(ER-2726): Add guards for Bitcoin concurrent access.
        Ok(Self {
            bitcoin_canister,
            main_address_type: *main_address_type,
            ecdsa_pub_key_addresses: HashMap::from([(
                main_address.clone(),
                get_btc_ecdsa_public_key(),
            )]),
            utxos_state_addresses: HashMap::from([(
                main_address,
                UtxosState::new(min_confirmations),
            )]),
        })
    }

    /// Returns the Bitcoin agent state.
    pub fn get_state(&self) -> BitcoinAgentState {
        upgrade_management::get_state(self)
    }

    /// Returns the associated Bitcoin agent with the given `bitcoin_agent_state`, assuming that it wasn't modified since its obtention with `get_state`.
    pub fn from_state(bitcoin_agent_state: BitcoinAgentState) -> Self {
        upgrade_management::from_state(bitcoin_agent_state)
    }

    /// Adds an address based on the provided derivation path and address type to the list of managed addresses.
    /// A minimum number of confirmations must further be specified, which is used when calling `get_utxos` and `get_balance`.
    /// Returns the derived address if the operation is successful and an error otherwise.
    pub fn add_address_with_parameters(
        &mut self,
        derivation_path: &[u8],
        address_type: &AddressType,
        min_confirmations: u32,
    ) -> Result<Address, AddAddressWithParametersError> {
        address_management::add_address_with_parameters(
            self,
            derivation_path,
            address_type,
            min_confirmations,
        )
    }

    /// Adds an address to the agent with the provided derivation path.
    /// The default address type and default number of confirmations are used.
    pub fn add_address(
        &mut self,
        derivation_path: &[u8],
    ) -> Result<Address, DerivationPathTooLong> {
        let address_type = self.main_address_type;
        let min_confirmations =
            self.utxos_state_addresses[&self.get_main_address()].min_confirmations;
        match self.add_address_with_parameters(derivation_path, &address_type, min_confirmations) {
            Err(AddAddressWithParametersError::DerivationPathTooLong) => Err(DerivationPathTooLong),
            Ok(address) => Ok(address),
            // Other case AddAddressWithParameters::MinConfirmationsTooHigh can't happen see BitcoinAgent::new
            _ => panic!(),
        }
    }

    /// Removes the given address from given BitcoinAgent managed addresses.
    /// The address is removed if it is already managed and if it is different from the main address.
    /// Returns true if the removal was successful, false otherwise.
    pub fn remove_address(&mut self, address: &Address) -> bool {
        address_management::remove_address(self, address)
    }

    /// Returns the managed addresses according to given BitcoinAgent.
    pub fn list_addresses(&self) -> Vec<&Address> {
        address_management::list_addresses(self)
    }

    // TODO(ER-2601): Box<dyn Error> is used for all get_p2*_adddress because some can raise multiple error types but should use instead proper error types.
    // TODO(ER-2587): Add support for address management, test spending UTXOs received on addresses of all supported types (relying on ER-2593).

    /// Returns the P2SH address from a given script hash.
    pub fn get_p2sh_address(&self, script_hash: &[u8]) -> Result<Address, Box<dyn Error>> {
        address_management::get_p2sh_address(&self.bitcoin_canister.get_network(), script_hash)
    }

    /// Returns the main Bitcoin address of the canister.
    pub fn get_main_address(&self) -> Address {
        address_management::get_main_address(
            &self.bitcoin_canister.get_network(),
            &self.main_address_type,
        )
    }

    /// Returns the UTXOs of the given Bitcoin `address` according to `min_confirmations`.
    pub async fn get_utxos(
        &self,
        address: &Address,
        min_confirmations: u32,
    ) -> Result<Vec<Utxo>, MinConfirmationsTooHigh> {
        self.bitcoin_canister
            .get_utxos(address, min_confirmations)
            .await
    }

    /// Returns the difference between the current UTXO state and the last seen state for this address.
    /// The last seen state for an address is updated to the current state by calling `update_state` or implicitly when invoking `get_utxos_update`.
    /// If there are no changes to the UTXO set since the last call, the returned `UtxosUpdate` will be identical.
    pub async fn peek_utxos_update(
        &mut self,
        address: &Address,
    ) -> Result<UtxosUpdate, AddressNotTracked> {
        utxo_management::peek_utxos_update(self, address).await
    }

    /// Updates the state of the `BitcoinAgent` for the given `address`.
    /// This function doesn't invoke a Bitcoin integration API function.
    pub fn update_state(&mut self, address: &Address) -> Result<(), AddressNotTracked> {
        utxo_management::update_state(self, address)
    }

    /// Returns the difference in the set of UTXOs of an address controlled by the `BitcoinAgent` between the current state and the seen state when the function was last called, considering only UTXOs with the number of confirmations specified when adding the given address.
    /// The returned `UtxosUpdate` contains the information which UTXOs were added and removed. If the function is called for the first time, the current set of UTXOs is returned.
    /// Note that the function changes the state of the `BitcoinAgent`: A subsequent call will return changes to the UTXO set that have occurred since the last call.
    pub async fn get_utxos_update(
        &mut self,
        address: &Address,
    ) -> Result<UtxosUpdate, AddressNotTracked> {
        utxo_management::get_utxos_update(self, address).await
    }

    /// Returns the balance of the given Bitcoin `address` according to `min_confirmations`.
    pub async fn get_balance(
        &self,
        address: &Address,
        min_confirmations: u32,
    ) -> Result<Satoshi, MinConfirmationsTooHigh> {
        utxo_management::get_balance(self, address, min_confirmations).await
    }

    /// Returns the difference between the current balance state and the last seen state for this address.
    /// The last seen state for an address is updated to the current unseen state by calling `update_state` or implicitly when invoking `get_balance_update`.
    /// If there are no changes to the balance since the last call, the returned `BalanceUpdate` will be identical.
    pub async fn peek_balance_update(
        &mut self,
        address: &Address,
    ) -> Result<BalanceUpdate, AddressNotTracked> {
        utxo_management::peek_balance_update(self, address).await
    }

    /// Returns the difference in the balance of an address controlled by the `BitcoinAgent` between the current state and the seen state when the function was last called, considering only transactions with the specified number of confirmations.
    /// The returned `BalanceUpdate` contains the information on how much balance was added and subtracted in total. If the function is called for the first time, the current balance of the address is returned.
    /// It is equivalent to calling `get_utxos_update` and summing up the balances in the returned UTXOs.
    pub async fn get_balance_update(
        &mut self,
        address: &Address,
    ) -> Result<BalanceUpdate, AddressNotTracked> {
        utxo_management::get_balance_update(self, address).await
    }
}

/// Creates a new instance of the Bitcoin agent using the Bitcoin canister mock.
#[cfg(test)]
pub(crate) fn new_mock(
    network: &Network,
    main_address_type: &AddressType,
) -> BitcoinAgent<BitcoinCanisterMock> {
    BitcoinAgent::new(
        BitcoinCanisterMock::new(from_bitcoin_network_to_types_network(*network)),
        main_address_type,
        0,
    )
    .unwrap()
}
