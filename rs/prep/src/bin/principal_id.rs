use ic_types::PrincipalId;
use openssl::pkey;
use std::{
    env,
    fs::File,
    io,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    string::ToString,
};
use structopt::StructOpt;

#[derive(Debug)]
enum PemOrDer {
    Pem,
    Der,
}

#[derive(Debug)]
struct PemOrDerParseError(());

impl ToString for PemOrDerParseError {
    fn to_string(&self) -> String {
        "Can't parse string. Not 'pem' nor 'der'".to_string()
    }
}

impl FromStr for PemOrDer {
    type Err = PemOrDerParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pem" => Ok(PemOrDer::Pem),
            "der" => Ok(PemOrDer::Der),
            _ => Err(PemOrDerParseError(())),
        }
    }
}

impl ToString for PemOrDer {
    fn to_string(&self) -> String {
        match self {
            PemOrDer::Pem => "pem",
            PemOrDer::Der => "der",
        }
        .to_string()
    }
}

#[derive(StructOpt, Debug)]
#[structopt(
    name = "ic-principal-id",
    about = r#"
Converts a multitude of formats into principal ids.

EXAMPLES:

  * Producing a principal id from a PEM file.
      $ ic-principal-id self-signed -i pubkey.pem

  * Produgin a principal id from a DER coming from stdin .
      $ ic-principal-id self-signed --type der

  * Producing a human readable version from raw bytes:
      $ ic-principal-id raw < raw_bytes_file
"#
)]
enum CliArgs {
    SelfSigned {
        #[structopt(short = "i", long = "input", parse(from_os_str))]
        file: Option<PathBuf>,

        #[structopt(short = "t", long = "type")]
        pem_or_der: Option<PemOrDer>,
    },
    Raw {
        #[structopt(short = "i", long = "input", parse(from_os_str))]
        file: Option<PathBuf>,
    },
}

pub fn ensure_file_exists(file: &Path) -> io::Result<()> {
    if !file.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File {} does not exist.", file.display()),
        ));
    }
    Ok(())
}

pub fn ensure_file_extension(file: &Path, ext: &str) -> io::Result<()> {
    if let Some(fext) = file.extension() {
        if fext.to_str().eq(&Some(ext)) {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("File {} doesn't have '{}' extension", file.display(), ext),
    ))
}

//Runs in self-signed mode, with options extract from CliArgs
fn run_self_signed(fname: Option<PathBuf>, pod: Option<PemOrDer>) -> io::Result<()> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut parser: PemOrDer = PemOrDer::Pem;

    //First we run all possible parameters options and at the end of this 'match'
    //block, we'll have the contents from the file into 'buffer' above and
    //whether it is a pem or der file in 'parser'.
    match fname {
        //No filename? No problem! we use stdin.
        None => {
            //the caveat is that the user must specify whether we're looking at PEM or DER
            // bytes.
            match pod {
                Some(tgt) => parser = tgt,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Must specify '--type' option when reading from stdin",
                    ))
                }
            }
            io::stdin().read_to_end(&mut buffer)?;
        }

        //We were given a file, alright. We'll make sure it exits
        Some(fname) => {
            ensure_file_exists(&fname)?;
            //And if the user specified an extension, we make sure the file has the right
            // extension, otherwise we try to figure it out whether its a PEM or
            // DER publickey from the file extension.
            match pod {
                Some(tgt) => {
                    ensure_file_extension(&fname, &tgt.to_string())?;
                    parser = tgt;
                }
                None => {
                    if let Some(ext) = fname.extension() {
                        parser = PemOrDer::from_str(ext.to_str().unwrap()).map_err(|_e| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("Can't parse file extension ({}).", fname.display()),
                            )
                        })?;
                    }
                }
            }
            File::open(fname)?.read_to_end(&mut buffer)?;
        }
    };

    //Finally, we're ready to do the actual work: read in the public key,
    //export it as der then calculate the principal_id. I chose to read the key
    //even when the input is supposed to be in der format as an extra validaton
    // step.
    let pkey = match parser {
        PemOrDer::Der => pkey::PKey::public_key_from_der(&buffer)?,
        PemOrDer::Pem => pkey::PKey::public_key_from_pem(&buffer)?,
    };
    let pkey_der = pkey.public_key_to_der()?;
    println!("{:?}", PrincipalId::new_self_authenticating(&pkey_der));
    Ok(())
}

//Runs in raw mode, with options extract from CliArgs
fn run_raw(fname: Option<PathBuf>) -> io::Result<()> {
    let mut buffer: Vec<u8> = Vec::new();

    let num_bytes = match fname {
        None => io::stdin().read_to_end(&mut buffer)?,
        Some(fname) => {
            ensure_file_exists(&fname)?;
            File::open(fname)?.read_to_end(&mut buffer)?
        }
    };

    if num_bytes >= PrincipalId::MAX_LENGTH_IN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Read too many bytes. PrincipalId's are bounded.",
        ));
    }

    let mut arr: [u8; PrincipalId::MAX_LENGTH_IN_BYTES] = Default::default();
    arr.copy_from_slice(&buffer[0..PrincipalId::MAX_LENGTH_IN_BYTES]);
    let pid = PrincipalId::new(num_bytes, arr);
    println!("{:?}", pid);
    Ok(())
}

fn main() -> io::Result<()> {
    let args = match CliArgs::from_iter_safe(env::args()) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    match args {
        CliArgs::SelfSigned { file, pem_or_der } => run_self_signed(file, pem_or_der),
        CliArgs::Raw { file } => run_raw(file),
    }
}
