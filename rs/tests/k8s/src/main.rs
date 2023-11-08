use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use k8s::tnet::TNet;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a testnet
    Create {
        /// Testnet name
        #[arg(short, long)]
        name: String,
        /// Testnet version
        #[arg(short, long)]
        version: String,
        /// Use a zero version within testnet
        #[arg(long)]
        use_zero_version: bool,
        /// NNS subnet size
        #[arg(long)]
        nns: usize,
        /// APP subnet size
        #[arg(long)]
        app: usize,
    },
    /// Delete a testnet
    Delete {
        /// Testnet name (excludes namespace)
        #[arg(short, long, conflicts_with = "namespace")]
        name: Option<String>,
        /// Testnet namespace
        #[arg(long)]
        namespace: Option<String>,
    },
    /// List all testnets
    List {},
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    match &cli.command {
        Some(Commands::Create {
            name,
            version,
            use_zero_version,
            nns,
            app,
        }) => {
            let _ = TNet::new(name)
                .version(version)
                .use_zero_version(*use_zero_version)
                .topology(*nns, *app)
                .create()
                .await?;
        }
        Some(Commands::Delete { name, namespace }) => {
            TNet::delete(name.clone(), namespace.clone()).await?;
        }
        Some(Commands::List {}) => {
            let list = TNet::list().await?;
            if list.is_empty() {
                println!("No resources found");
            } else {
                println!(" {:>10}     NAME", "NAMESPACE");
                for (ns, name) in list {
                    println!(" {:>10}  ⎈  {}", ns, name);
                }
            }
        }
        None => {}
    }

    Ok(())
}
