use anyhow::{Context, Error};
use ic_stable_structures::{Memory, writer::Writer};
use serde::{de::DeserializeOwned, ser::Serialize};

pub fn store<M: Memory, T: Serialize>(mut m: M, v: T) -> Result<(), Error> {
    // Serialize
    let inner = bincode::serialize(&v)?;

    // Store
    let mut w = Writer::new(&mut m, 0);

    // Length
    w.write(&(inner.len() as u32).to_le_bytes())
        .context("failed to write data length")?;

    // Content
    w.write(&inner).context("failed to write data")?;

    Ok(())
}

pub fn load<M: Memory, T: DeserializeOwned>(m: M) -> Result<T, Error> {
    // Length
    let mut len_bytes = [0; 4];
    m.read(0, &mut len_bytes);
    let len = u32::from_le_bytes(len_bytes) as usize;

    // Content
    let mut inner = vec![0; len];
    m.read(4, &mut inner);

    // Deserialize
    let v: T = bincode::deserialize(&inner)?;

    Ok(v)
}
