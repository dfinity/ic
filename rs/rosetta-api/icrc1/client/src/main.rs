use candid::Nat;
use clap::{Parser, Subcommand};
use ic_agent::identity::BasicIdentity;
use ic_icrc_rosetta_client::RosettaClient;
use icrc_ledger_types::icrc1::account::Account;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, Subcommand)]
enum OperationType {
    Approve {
        /// The amount of tokens to approve the spender the spend on the sender's behalf
        #[arg(long)]
        allowance: Nat,

        /// The time at which the approved allowance expires
        #[arg(long)]
        expires_at: Option<u64>,

        /// The ledger must ensure that the current allowance for the spender from the caller's account is equal to the given value
        #[arg(long)]
        expected_allowance: Option<Nat>,

        /// The account of the spender
        #[arg(long)]
        spender: Account,

        /// The subaccount of the sender. If set it has to be a non empty 32 byte vector.
        #[arg(long)]
        from_subaccount: Option<String>,

        /// A vector of maximum 32 bytes that is attached to the transaction for arbitrary data.
        #[arg(long)]
        memo: Option<String>,

        /// The created_at_time timestamp that is set in the transaction. It triggers the deduplication window.
        #[arg(long)]
        created_at_time: Option<u64>,
    },
    Transfer {
        /// The amount of tokens to transfer
        #[arg(long)]
        amount: Nat,

        /// The account of the recipient
        #[arg(long)]
        to: Account,

        /// The subaccount of the sender. If set it has to be a non empty 32 byte vector.
        #[arg(long)]
        from_subaccount: Option<String>,

        /// A vector of maximum 32 bytes that is attached to the transaction for arbitrary data.
        #[arg(long)]
        memo: Option<String>,

        /// The created_at_time timestamp that is set in the transaction. It triggers the deduplication window.
        #[arg(long)]
        created_at_time: Option<u64>,
    },

    TransferFrom {
        /// The amount of tokens to transfer
        #[arg(long)]
        amount: Nat,

        /// The account of the credited account
        #[arg(long)]
        to: Account,

        /// The account of the debited account
        #[arg(long)]
        from: Account,

        /// The subaccount of the spender. If set it has to be a non empty 32 byte vector.
        #[arg(long)]
        spender_subaccount: Option<String>,

        /// A vector of maximum 32 bytes that is attached to the transaction for arbitrary data.
        #[arg(long)]
        memo: Option<String>,

        /// The created_at_time timestamp that is set in the transaction. It triggers the deduplication.
        #[arg(long)]
        created_at_time: Option<u64>,
    },
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The type of operation to perform
    #[clap(subcommand)]
    operation_type: OperationType,

    /// The URL of the rosetta server
    #[arg(short, long)]
    rosetta_url: String,

    /// The path to the pem file of the sender
    #[arg(short, long)]
    sender_pem_file: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = Args::parse();
    let rosetta_client = RosettaClient::from_str_url(&args.rosetta_url)?;

    let file = match std::fs::File::open(args.sender_pem_file.clone()) {
        Ok(file) => file,
        Err(e) => {
            anyhow::bail!("Failed to open file {:?}: {:?}", args.sender_pem_file, e);
        }
    };

    let network_identifier = &rosetta_client
        .network_list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get network list: {:?}", e))?
        .network_identifiers[0];

    let sender_keypair = Arc::new(BasicIdentity::from_pem(file)?);

    match args.operation_type {
        OperationType::Approve {
            allowance,
            expires_at,
            expected_allowance,
            spender,
            from_subaccount,
            memo,
            created_at_time,
        } => {
            let from_subaccount: Option<[u8; 32]> = from_subaccount
                .map(|s| s.as_bytes().try_into())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;

            let memo: Option<Vec<u8>> = memo.map(|s| s.as_bytes().to_vec());

            let operations = rosetta_client
                .build_approve_operations(
                    &sender_keypair,
                    from_subaccount,
                    spender,
                    allowance,
                    expected_allowance,
                    network_identifier.clone(),
                    expires_at,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to build approve operations: {:?}", e))?;

            rosetta_client
                .make_submit_and_wait_for_transaction(
                    &sender_keypair,
                    network_identifier.clone(),
                    operations,
                    memo,
                    created_at_time,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to make and submit transaction: {:?}", e))?
        }
        OperationType::Transfer {
            amount,
            to: to_account,
            from_subaccount,
            memo,
            created_at_time,
        } => {
            let from_subaccount: Option<[u8; 32]> = from_subaccount
                .map(|s| s.as_bytes().try_into())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;

            let memo: Option<Vec<u8>> = memo.map(|s| s.as_bytes().to_vec());

            let operations = rosetta_client
                .build_transfer_operations(
                    &sender_keypair,
                    from_subaccount,
                    to_account,
                    amount,
                    network_identifier.clone(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to build transfer operations: {:?}", e))?;

            rosetta_client
                .make_submit_and_wait_for_transaction(
                    &sender_keypair,
                    network_identifier.clone(),
                    operations,
                    memo,
                    created_at_time,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to make and submit transaction: {:?}", e))?
        }
        OperationType::TransferFrom {
            amount,
            to: to_account,
            from: from_account,
            spender_subaccount,
            memo,
            created_at_time,
        } => {
            let spender_subaccount: Option<[u8; 32]> = spender_subaccount
                .map(|s| s.as_bytes().try_into())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;

            let memo: Option<Vec<u8>> = memo.map(|s| s.as_bytes().to_vec());

            let operations = rosetta_client
                .build_transfer_from_operations(
                    &sender_keypair,
                    spender_subaccount,
                    to_account,
                    from_account,
                    amount,
                    network_identifier.clone(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to build transfer from operations: {:?}", e)
                })?;

            rosetta_client
                .make_submit_and_wait_for_transaction(
                    &sender_keypair,
                    network_identifier.clone(),
                    operations,
                    memo,
                    created_at_time,
                )
                .await
                .map_err(|e| anyhow::anyhow!("Failed to make and submit transaction: {:?}", e))?
        }
    };
    Ok(())
}
