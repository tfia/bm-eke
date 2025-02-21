use std::io::{Read, Result, Write};
use log::error;
use zuc::{
    cipher::{Key, KeyIvInit, StreamCipher},
    zuc128::Zuc128StreamCipher,
};

/// ZUC-128 encrypt & send wrapper.
/// Sends nonce, data length, and encrypted data in order.
pub fn zuc_send<W: Write>(
    pw: Key<Zuc128StreamCipher>,
    stream: &mut W,
    data: &[u8],
) -> Result<()> {
    let nonce: [u8; 16] = rand::random(); // this must be 16 bytes
    let mut cipher = Zuc128StreamCipher::new_from_slices(&pw, &nonce).map_err(|e| {
        error!("Error: {:?}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "Cipher initialization failed")
    })?;
    let mut data = data.to_vec();
    cipher.apply_keystream(&mut data);
    stream.write_all(&nonce)?;
    stream.write_all(&data.len().to_le_bytes())?;
    stream.write_all(&data)?;
    Ok(())
}

/// ZUC-128 receive & decrypt wrapper.
/// Receives nonce, data length, and encrypted data in order.
/// Returns decrypted data.
pub fn zuc_receive<T: Into<Key<Zuc128StreamCipher>>, R: Read>(
    pw: T,
    stream: &mut R,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    stream.read_exact(&mut nonce)?;
    let mut len = [0u8; 8];
    stream.read_exact(&mut len)?;
    let len = usize::from_le_bytes(len);
    let mut cipher = Zuc128StreamCipher::new_from_slices(&pw.into(), &nonce).map_err(|e| {
        error!("Error: {:?}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "Cipher initialization failed")
    })?;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}
