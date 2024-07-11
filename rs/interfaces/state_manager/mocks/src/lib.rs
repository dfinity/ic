use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_state_manager::{
    CertificationMask, CertificationScope, CertifiedStateSnapshot, Labeled, StateHashError,
    StateManager, StateManagerResult, StateReader,
};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    batch::BatchSummary, consensus::certification::Certification, CryptoHashOfPartialState,
    CryptoHashOfState, Height,
};
use mockall::*;
use std::sync::Arc;

mock! {
    pub StateManager {}

    impl StateReader for StateManager {
        type State = ReplicatedState;

        fn get_state_at(&self, height: Height) -> StateManagerResult<Labeled<Arc<ReplicatedState>>>;

        fn get_latest_state(&self) -> Labeled<Arc<ReplicatedState>>;

        fn latest_state_height(&self) -> Height;

        fn latest_certified_height(&self) -> Height;

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>
        ) -> Option<(Arc<ReplicatedState>, MixedHashTree, Certification)>;

        fn get_certified_state_snapshot(&self) -> Option<Box<dyn CertifiedStateSnapshot<State = <MockStateManager as StateReader>::State> + 'static>>;
    }

    impl StateManager for StateManager {
        fn take_tip(&self) -> (Height, ReplicatedState);

        fn take_tip_at(&self, h: Height) -> StateManagerResult<ReplicatedState>;

        fn get_state_hash_at(&self, height: Height) -> Result<CryptoHashOfState, StateHashError>;

        fn fetch_state(&self, height: Height, root_hash: CryptoHashOfState, cup_interval_length: Height);

        fn list_state_hashes_to_certify(&self) -> Vec<(Height, CryptoHashOfPartialState)>;

        fn deliver_state_certification(&self, certification: Certification);

        fn list_state_heights(
            &self,
            cert_mask: CertificationMask,
        ) -> Vec<Height>;

        fn remove_states_below(&self, height: Height);

        fn remove_inmemory_states_below(&self, height: Height);

        fn commit_and_certify(
            &self,
            state: ReplicatedState,
            height: Height,
            scope: CertificationScope,
            batch_summary: Option<BatchSummary>,
        );

        fn report_diverged_checkpoint(&self, height: Height);
    }
}
