/*!
Crypto things
*/
use crate::errors::*;
use ring;

/// Return a `Vec` of secure random bytes of size `n`
pub fn rand_bytes(n: usize) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut buf = vec![0; n];
    let sysrand = ring::rand::SystemRandom::new();
    sysrand.fill(&mut buf)?;
    Ok(buf)
}

/// Return the SHA256 hash of `bytes`
pub fn hash(bytes: &[u8]) -> Vec<u8> {
    let alg = &ring::digest::SHA256;
    let digest = ring::digest::digest(alg, bytes);
    Vec::from(digest.as_ref())
}

/// Encrypt `bytes` with the given `nonce` and `pass`
///
/// `bytes` are encrypted using AES_256_GCM, `nonce` is expected to be
/// 12-bytes, and `pass` 32-bytes
pub fn encrypt<'a>(bytes: &[u8], nonce: &[u8], pass: &[u8]) -> Result<Vec<u8>> {
    let alg = &ring::aead::AES_256_GCM;
    let key = ring::aead::SealingKey::new(alg, pass)?;

    let out_suffix_tag_len = key.algorithm().tag_len();
    let mut in_out = bytes.to_vec();
    // make sure we have enough room for the out suffix-tag
    in_out.resize(bytes.len() + out_suffix_tag_len, 0);

    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce)?;
    let out_len = ring::aead::seal_in_place(
        &key,
        nonce,
        ring::aead::Aad::empty(),
        &mut in_out,
        out_suffix_tag_len,
    )?;
    in_out.truncate(out_len);
    Ok(in_out)
}

/// Decrypt `bytes` with the given `nonce` and `pass`
///
/// `bytes` are decrypted using AES_256_GCM, `nonce` is expected to be
/// 12-bytes, and `pass` 32-bytes
pub fn decrypt<'a>(bytes: &'a mut [u8], nonce: &[u8], pass: &[u8]) -> Result<&'a [u8]> {
    let alg = &ring::aead::AES_256_GCM;
    let key = ring::aead::OpeningKey::new(alg, pass)?;
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce)?;
    let out_slice = ring::aead::open_in_place(&key, nonce, ring::aead::Aad::empty(), 0, bytes)?;
    Ok(out_slice)
}
