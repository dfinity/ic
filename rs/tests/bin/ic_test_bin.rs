//! This programs creates a fully functional local internet computer.
//! See --help (or the docstring below) for details.

use ic_fondue::{
    self,
    ic_instance::InternetComputer,
    ic_manager::{IcManager, IcManagerSettings},
};
use ic_registry_subnet_type::SubnetType;
use ic_tests::util::block_on;
use slog::info;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "ic-test-bin", no_version)]

struct CliArgs {
    /// Target an app subnet
    ///
    /// Also starts an application subnet, and uses that in endpoint
    #[structopt(long)]
    use_app_subnet: bool,

    #[structopt(long, parse(from_os_str))]
    /// Once everything is up, write the endpoint URL of the public interface to
    /// this file
    endpoint: Option<PathBuf>,

    #[structopt(long, parse(from_os_str))]
    /// Once everything is up, write the registry local store path to this
    /// file
    registry_local_store: Option<PathBuf>,
}

fn main() {
    ic_fondue::register_double_ctrlc_kill().expect("Couldn't register double Ctrl+C handler");
    let args = CliArgs::from_args();
    let mut ic = InternetComputer::new();

    ic = ic.add_fast_single_node_subnet(SubnetType::System);
    if args.use_app_subnet {
        ic = ic.add_fast_single_node_subnet(SubnetType::Application);
    }

    let mut fondue_cfg = ic_fondue::pot::Config::default();
    fondue_cfg.level = slog::Level::Debug;
    fondue_cfg.ready_timeout = std::time::Duration::from_secs(600);

    let res = ic_fondue::pot::from_isolated("ic-test-bin", &ic, wait_for_sigint(args))
        .run_with(&fondue_cfg, IcManagerSettings::default());

    if !res.is_success() {
        std::process::exit(1);
    }
}

fn wait_for_sigint(args: CliArgs) -> impl FnOnce(IcManager, &ic_fondue::pot::Context) {
    move |man, ctx| {
        let handle = man.handle();
        if let Some(ref path) = args.endpoint {
            if args.use_app_subnet {
                let app_endpoint = handle
                    .public_api_endpoints
                    .iter()
                    .find(|i| !i.is_root_subnet)
                    .expect("empty iterator");
                // TODO(VER-963): wait until the endpoint is ready directly in ic-ref-test.
                block_on(app_endpoint.assert_ready(ctx));
                info!(
                    ctx.logger,
                    "ic-test-bin ready at {}, use Ctrl-C to stop", app_endpoint.url
                );
                fs::write(path, app_endpoint.url.as_str()).unwrap();
            } else {
                let root_endpoint = handle
                    .public_api_endpoints
                    .iter()
                    .find(|i| i.is_root_subnet)
                    .expect("empty iterator");
                block_on(root_endpoint.assert_ready(ctx));
                info!(
                    ctx.logger,
                    "ic-test-bin ready at {}, use Ctrl-C to stop", root_endpoint.url
                );
                fs::write(path, root_endpoint.url.as_str()).unwrap();
            }
        }

        if let Some(ref path) = args.registry_local_store {
            let contents = man
                .handle()
                .ic_prep_working_dir
                .unwrap()
                .registry_local_store_path()
                .into_os_string()
                .into_string()
                .unwrap();
            fs::write(path, contents).unwrap();
        }

        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
