//! NaCl `crypto_secretbox` (XSalsa20-Poly1305) for the obfs4 framing layer.
//!
//! Built from `salsa20` and `poly1305` because `crypto_secretbox` has no
//! stable release on `cipher` 0.5. The construction is NaCl's: the first 32
//! keystream bytes are the one-time Poly1305 key, the message is XORed with
//! the keystream from byte 32 on, and the tag is the unpadded Poly1305 of the
//! ciphertext. Wire format and the test vectors below are unchanged.

use poly1305::{universal_hash::KeyInit, Poly1305};
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    XSalsa20,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const KEY_SIZE: usize = 32;
pub(crate) const NONCE_SIZE: usize = 24;
pub(crate) const TAG_SIZE: usize = 16;

/// Authentication failed: the ciphertext or the tag was altered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("secretbox authentication failed")
    }
}

impl std::error::Error for Error {}

/// A secretbox key; wiped on drop.
pub(crate) struct SecretBox {
    key: Zeroizing<[u8; KEY_SIZE]>,
}

impl SecretBox {
    pub(crate) fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self {
            key: Zeroizing::new(*key),
        }
    }

    /// Keystream positioned after the Poly1305 key, and that key's MAC.
    fn start(&self, nonce: &[u8; NONCE_SIZE]) -> (XSalsa20, Poly1305) {
        let mut cipher = XSalsa20::new(&(*self.key).into(), &(*nonce).into());
        let mut mac_key = Zeroizing::new([0u8; KEY_SIZE]);
        cipher.apply_keystream(&mut mac_key[..]);
        let mac = Poly1305::new(&(*mac_key).into());
        (cipher, mac)
    }

    /// Encrypt `buffer` in place and return its tag.
    pub(crate) fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        buffer: &mut [u8],
    ) -> [u8; TAG_SIZE] {
        let (mut cipher, mac) = self.start(nonce);
        cipher.apply_keystream(buffer);
        mac.compute_unpadded(buffer).into()
    }

    /// Check `tag` in constant time, then decrypt `buffer` in place. On
    /// failure `buffer` is left as the untouched ciphertext.
    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        buffer: &mut [u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<(), Error> {
        let (mut cipher, mac) = self.start(nonce);
        let expected: [u8; TAG_SIZE] = mac.compute_unpadded(buffer).into();
        if !bool::from(expected.ct_eq(tag)) {
            return Err(Error);
        }
        cipher.apply_keystream(buffer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NaCl `tests/secretbox.c` (Bernstein, "Cryptography in NaCl"): the
    // 131-byte message after its 32 zero bytes, sealed with `firstkey` and
    // `nonce`. Output is the 16-byte tag followed by the ciphertext.
    const KEY: [u8; 32] =
        hex_literal::hex!("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    const NONCE: [u8; 24] = hex_literal::hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    const PLAINTEXT: [u8; 131] = hex_literal::hex!(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
        "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
        "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
        "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864"
        "5e0705"
    );
    const SEALED: [u8; 147] = hex_literal::hex!(
        "f3ffc7703f9400e52a7dfb4b3d3305d9"
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
        "e355a5"
    );

    #[test]
    fn matches_the_nacl_reference_vector() {
        let secretbox = SecretBox::new(&KEY);
        let mut buffer = PLAINTEXT;
        let tag = secretbox.seal_in_place(&NONCE, &mut buffer);
        assert_eq!(tag[..], SEALED[..TAG_SIZE]);
        assert_eq!(buffer[..], SEALED[TAG_SIZE..]);

        secretbox
            .open_in_place(&NONCE, &mut buffer, &tag)
            .expect("open");
        assert_eq!(buffer, PLAINTEXT);
    }

    #[test]
    fn any_flipped_bit_is_rejected_and_leaves_the_ciphertext() {
        let secretbox = SecretBox::new(&KEY);
        let tag: [u8; TAG_SIZE] = SEALED[..TAG_SIZE].try_into().unwrap();
        for bit in 0..SEALED.len() * 8 {
            let mut sealed = SEALED;
            sealed[bit / 8] ^= 1 << (bit % 8);
            let bad_tag: [u8; TAG_SIZE] = sealed[..TAG_SIZE].try_into().unwrap();
            let mut body = sealed[TAG_SIZE..].to_vec();
            assert_eq!(
                secretbox.open_in_place(&NONCE, &mut body, &bad_tag),
                Err(Error),
                "bit {bit}"
            );
            assert_eq!(body[..], sealed[TAG_SIZE..], "bit {bit}");
        }
        let mut body = SEALED[TAG_SIZE..].to_vec();
        secretbox
            .open_in_place(&NONCE, &mut body, &tag)
            .expect("untouched box opens");
    }

    #[test]
    fn empty_message_has_a_tag_and_round_trips() {
        let secretbox = SecretBox::new(&KEY);
        let tag = secretbox.seal_in_place(&NONCE, &mut []);
        secretbox
            .open_in_place(&NONCE, &mut [], &tag)
            .expect("open");
        let mut wrong = tag;
        wrong[0] ^= 1;
        assert_eq!(secretbox.open_in_place(&NONCE, &mut [], &wrong), Err(Error));
    }
}
