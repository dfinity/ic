use nftables::{
    helper::get_current_ruleset,
    schema::NfObject,
    schema::NfListObject::Counter,
};
use anyhow::{anyhow, Context, Error};

fn main() -> Result<(), Error> {
    let nft_ruleset = get_current_ruleset(None, None).context("failed to get the current nft ruleset")?;

    for nft_object in nft_ruleset.objects.iter() {
        match nft_object {
            NfObject::ListObject(Counter(counter)) => {
                println!("Counter:\n\tfamily {}\n\ttable {}\n\tname {}\n\thandle {:?}\n\tpackets {:?}\n\tbytes {:?}\n", counter.family, counter.table, counter.name, counter.handle, counter.packets, counter.bytes);
            }
            _ => {}
        }

    }

    Ok(())
}
