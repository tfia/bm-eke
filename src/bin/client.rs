use anyhow::Result;
use clap::Parser;
use log::{info, error};
use rsa::{pkcs1::EncodeRsaPublicKey, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::{
    io::Write,
    net::TcpStream,
};
use zuc::digest::generic_array::GenericArray;

use bm::cli::Cli;
use bm::tcp::{zuc_receive, zuc_send};

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    info!("Client starting...");
    let args = Cli::parse();

    info!("Connecting to server...");
    let mut stream = TcpStream::connect(format!("{}:{}", args.addr, args.port))?;
    info!("Connected to server: {}", stream.peer_addr()?);

    /* Step 1: Generate new RSA keypair (pk_A, sk_A),
    then send identity and encrypted pk_A to server.
    pk_A should be encrypted with pw using ZUC-128. */
    info!("Generating RSA keypair...");
    let mut rng = rand::thread_rng(); // requires `rand` 0.8.5!
    let sk_a = RsaPrivateKey::new(&mut rng, 2048)?;
    let pk_a = RsaPublicKey::from(&sk_a);
    info!("RSA keypair generated.");
    let id: [u8; 4] = rand::random();
    info!("Generated identity: {:?}", id);
    stream.write_all(&id)?;
    info!("Sent identity to server.");
    let pk_bytes = pk_a.to_pkcs1_der()?.to_vec();
    zuc_send(args.pw, &mut stream, &pk_bytes)?;
    info!("Sent encrypted pk_A to server.");

    /* Step 2: Receive ZUC(pw, RSA(pk_A, K_s)) from server. */
    let k_s_enc = zuc_receive(args.pw, &mut stream)?;
    info!("Received K_s from server");

    /* Step 3: Decrypt K_s,
    generate random number N_A,
    and send ZUC(K_s, N_A) to server. */
    let k_s = sk_a.decrypt(Pkcs1v15Encrypt, &k_s_enc)?;
    let k_s = GenericArray::from_slice(&k_s);
    info!("Decrypted K_s: {:?}", k_s);
    let n_a: u128 = rand::random(); // 256 bit is enough?
    info!("Generated N_A: {:?}", n_a);
    zuc_send(*k_s, &mut stream, &n_a.to_le_bytes())?;

    /* Step4: Receive ZUC(K_s, N_1||N_2) from server. */
    let n_12 = zuc_receive(*k_s, &mut stream)?;
    let n_1 = u128::from_le_bytes(n_12[..16].try_into().unwrap());
    info!("Received N_1: {:?}", n_1);

    /* Step5: Verify that N_1 equals to N_A.
    Send ZUC(K_s, N_2) to server. */
    if n_1 != n_a {
        error!("N_1 != N_A. Handshake failed.");
        return Err(anyhow::anyhow!("N_1 != N_A"));
    }
    info!("N_1 == N_A. Server verified.");
    zuc_send(*k_s, &mut stream, &n_12[16..])?;

    Ok(())
}
