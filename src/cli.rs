use clap::Parser;
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use zuc::cipher::Key;
use zuc::zuc128::Zuc128StreamCipher;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    // address to bind to
    #[arg(short, long, default_value = "127.0.0.1")]
    pub addr: String,
    // port to bind to
    #[arg(short, long, default_value = "7878")]
    pub port: u16,
    // shared pw
    // this should be generated from the Initial Key Material (IKM)
    // and a salt
    #[arg(long, value_parser = gen_pw)]
    pub pw: Key<Zuc128StreamCipher>,
}

pub const SALT: &[u8] = b"bm-salt";
pub const INFO: &[u8] = b"bm-info";

/// generate ZUC-128 key from a user-provided string
fn gen_pw(pw: &str) -> Result<Key<Zuc128StreamCipher>> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), pw.as_bytes());
    let mut key = Key::<Zuc128StreamCipher>::default();
    hk.expand(INFO, &mut key).unwrap();
    Ok(key)
}
    