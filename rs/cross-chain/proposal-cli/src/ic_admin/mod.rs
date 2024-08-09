use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct IcAdminArgs {
    /// Use an HSM to sign calls.
    #[clap(long)]
    use_hsm: bool,

    /// The slot related to the HSM key that shall be used.
    #[clap(
        long = "slot",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    hsm_slot: Option<String>,

    /// The id of the key on the HSM that shall be used.
    #[clap(
        long = "key-id",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    key_id: Option<String>,

    /// The PIN used to unlock the HSM.
    #[clap(
        long = "pin",
        help = "Only required if use-hsm is set. Ignored otherwise."
    )]
    pin: Option<String>,

    #[clap(long)]
    /// The id of the neuron on behalf of which the proposal will be submitted.
    proposer: Option<u64>,

    /// The title of the proposal.
    #[clap(long)]
    proposal_title: Option<String>,
}
