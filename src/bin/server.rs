use anyhow::Result;
use clap::Parser;
use hkdf::Hkdf;
use log::{info, error};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::Sha256;
use zuc::zuc128::Zuc128StreamCipher;
use std::io::Read;
use std::net::TcpListener;
use zuc::cipher::Key;

use bm::cli::{Cli, INFO, SALT};
use bm::tcp::{zuc_receive, zuc_send};

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    info!("Starting server...");
    let args = Cli::parse();

    let listener = TcpListener::bind(format!("{}:{}", args.addr, args.port))?;
    info!("Listening on {}", listener.local_addr()?);
    info!("Shared pw: {:?}", args.pw);

    for stream in listener.incoming() {
        let mut stream = stream?;
        info!("Connection established: {}", stream.peer_addr()?);

        /* Step 1: Client will send its identity first,
        then send a RSA pub key encrypted with pw using ZUC-128. */
        let mut id = [0u8; 4];
        stream.read_exact(&mut id)?;
        info!("Received identity: {:?}", id);
        let pk_bytes = zuc_receive(args.pw, &mut stream)?;
        let pk_a = RsaPublicKey::from_pkcs1_der(&pk_bytes);
        if let Err(e) = pk_a {
            error!("Failed to parse pk_A: {:?}. Handshake failed.", e);
            continue;
        }
        let pk_a = pk_a.unwrap();
        info!("Received pk_A from client.");

        /* Step 2: Randomly generate ZUC-128 key K_s,
        and send ZUC(pw, RSA(pk_A, K_s)) to client. */
        let nonce: [u8; 16] = rand::random();
        let hk = Hkdf::<Sha256>::new(Some(SALT), &nonce);
        let mut k_s = Key::<Zuc128StreamCipher>::default();
        hk.expand(INFO, &mut k_s).unwrap();
        info!("Generated K_s: {:?}", k_s);
        let mut rng = rand::thread_rng();
        let k_s_enc = pk_a.encrypt(&mut rng, Pkcs1v15Encrypt, &k_s)?;
        zuc_send(args.pw, &mut stream, &k_s_enc)?;

        /* Step 3: Receive ZUC(K_s, N_A) from client. */
        let n_a = zuc_receive(k_s, &mut stream)?;
        let n_a = match n_a.try_into() {
            Ok(arr) => u128::from_le_bytes(arr),
            Err(e) => {
                error!("Failed to convert received data to u128: {:?}. Handshake failed.", e);
                continue;
            }
        };
        info!("Received N_A: {:?}", n_a);

        /* Step 4: Randomly generate N_B,
        and send ZUC(K_s, N_A||N_B) to client. */
        let n_b: u128 = rand::random();
        info!("Generated N_B: {:?}", n_b);
        let mut n_ab = vec![];
        n_ab.extend_from_slice(&n_a.to_le_bytes());
        n_ab.extend_from_slice(&n_b.to_le_bytes());
        zuc_send(k_s, &mut stream, &n_ab)?;

        /* Step 5: Receive ZUC(K_s, N_2) from client. */
        let n_2 = zuc_receive(k_s, &mut stream)?;
        let n_2 = match n_2.try_into() {
            Ok(arr) => u128::from_le_bytes(arr),
            Err(e) => {
                error!("Failed to convert received data to u128: {:?}. Handshake failed.", e);
                continue;
            }
        };

        /* Step 6: Verify that N_2 equals to N_b. */
        if n_2 != n_b {
            error!("N_2 != N_B. Handshake failed.");
            continue;
        }
        info!("N_2 == N_B. Client with identity {:?} verified.", id);
    }

    Ok(())
}
