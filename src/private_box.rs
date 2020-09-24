use core::mem::size_of;
use ssb_crypto::{PublicKey, SecretKey};
use zerocopy::{AsBytes, FromBytes};

// TODO: turns out these things are used for more than just the handshake,
// so the ssb_crypto submodule should probably be renamed.
use ssb_crypto::ephemeral::{
    derive_shared_secret_pk, derive_shared_secret_sk, generate_ephemeral_keypair, EphPublicKey,
};
use ssb_crypto::secretbox::{Hmac, Key, Nonce};

const MAX_RECIPIENTS: usize = 32;

/// libsodium must be initialised before calling `encrypt` or `decrypt`.
/// If you're using other libsodium based libraries that already initialise libsodium, you can omit
/// the call to `init`.
#[cfg(feature = "sodium")]
pub fn init() {
    ssb_crypto::sodium::init();
}

#[derive(AsBytes, FromBytes)]
#[repr(C, packed)]
struct MsgKey {
    recp_count: u8,
    key: Key,
}
impl MsgKey {
    fn zeroed() -> MsgKey {
        MsgKey {
            recp_count: 0,
            key: Key([0; 32]),
        }
    }
    fn as_array(&self) -> [u8; 33] {
        let mut out = [0; 33];
        out.copy_from_slice(self.as_bytes());
        out
    }
}

#[derive(AsBytes, FromBytes)]
#[repr(C, packed)]
struct BoxedKey {
    hmac: Hmac,
    msg_key: [u8; 33],
}

/// == 72 + recps.len() * 49 + text.len()
pub fn encrypted_size(text: &[u8], recps: &[PublicKey]) -> usize {
    size_of::<Nonce>()                        //   24
        + size_of::<EphPublicKey>()           // + 32
        + recps.len() * size_of::<BoxedKey>() // + recps.len() * 49
        + size_of::<Hmac>()                   // + 16
        + text.len()
}

fn set_prefix<'a>(buf: &'a mut [u8], prefix: &[u8]) -> &'a mut [u8] {
    let (p, rest) = buf.split_at_mut(prefix.len());
    p.copy_from_slice(prefix);
    rest
}

/// Takes the message you want to encrypt, and an array of recipient public keys.
/// Returns a message that is encrypted to all recipients and openable by them
/// with `private_box::decrypt`. The number of recipients must be between 1 and 32.
///
/// The encrypted length will be 56 + (recipients.len() * 33) + plaintext.len().
///
/// # Example
/// ```
/// extern crate private_box;
/// extern crate ssb_crypto;
///
/// use private_box::{encrypt, decrypt};
/// use ssb_crypto::Keypair;
///
/// fn main() {
///     let msg = "hello!".as_bytes();
///
///     let alice = Keypair::generate();
///     let bob = Keypair::generate();
///
///     let recps = [alice.public, bob.public];
///     let cypher = encrypt(msg, &recps);
///
///     let alice_result = decrypt(&cypher, &alice.secret);
///     let bob_result = decrypt(&cypher, &bob.secret);
///
///     assert_eq!(alice_result.unwrap(), msg);
///     assert_eq!(bob_result.unwrap(), msg);
/// }
/// ```
pub fn encrypt(plaintext: &[u8], recipients: &[PublicKey]) -> Vec<u8> {
    let mut out = vec![0; encrypted_size(plaintext, recipients)];
    encrypt_into(plaintext, recipients, &mut out);
    out
}

pub fn encrypt_into(plaintext: &[u8], recipients: &[PublicKey], mut out: &mut [u8]) {
    if recipients.len() > MAX_RECIPIENTS || recipients.len() == 0 {
        panic!(
            "Number of recipients must be less than {}, greater than 0",
            MAX_RECIPIENTS
        );
    }
    assert!(out.len() >= encrypted_size(plaintext, recipients));

    let nonce = Nonce::generate();
    let (eph_pk, eph_sk) = generate_ephemeral_keypair();

    let mkey = MsgKey {
        recp_count: recipients.len() as u8,
        key: Key::generate(),
    };

    let mut rest = set_prefix(&mut out, nonce.as_bytes());
    let rest = set_prefix(&mut rest, eph_pk.as_bytes());
    let (keys, rest) = rest.split_at_mut(recipients.len() * size_of::<BoxedKey>());
    let mut keychunks = keys.chunks_mut(size_of::<BoxedKey>());

    for pk in recipients {
        let kkey = Key(derive_shared_secret_pk(&eph_sk, pk).unwrap().0);
        let mut msg_key = mkey.as_array();
        let hmac = kkey.seal(&mut msg_key, &nonce);
        keychunks
            .next()
            .unwrap()
            .copy_from_slice(BoxedKey { hmac, msg_key }.as_bytes());
    }

    let (hmac_buf, text) = rest.split_at_mut(Hmac::SIZE);
    text.copy_from_slice(plaintext);

    let hmac = mkey.key.seal(text, &nonce);
    hmac_buf.copy_from_slice(hmac.as_bytes());
}

const BOXED_KEY_SIZE_BYTES: usize = 32 + 1 + 16;

/// Attempt to decrypt a private-box message, using your secret key.
/// If you were an intended recipient then the decrypted message is
/// returned as `Some(Vec<u8>)`. If it was not for you, then `None`
/// will be returned.
///
/// # Example
/// ```
/// extern crate private_box;
/// extern crate ssb_crypto;
///
/// use private_box::{encrypt, decrypt};
/// use ssb_crypto::Keypair;
///
/// fn main() {
///     let msg = "hello!".as_bytes();
///
///     let alice = Keypair::generate();
///     let bob = Keypair::generate();
///
///     let recps = [alice.public, bob.public];
///     let cypher = encrypt(msg, &recps);
///
///     let alice_result = decrypt(&cypher, &alice.secret);
///     let bob_result = decrypt(&cypher, &bob.secret);
///
///     assert_eq!(&alice_result.unwrap(), &msg);
///     assert_eq!(&bob_result.unwrap(), &msg);
/// }
///```
pub fn decrypt(cyphertext: &[u8], secret_key: &SecretKey) -> Option<Vec<u8>> {
    let nonce = Nonce::from_slice(&cyphertext[0..24])?;
    let eph_pk = EphPublicKey::from_slice(&cyphertext[24..56])?;

    let kkey = Key(derive_shared_secret_sk(secret_key, &eph_pk)?.0);
    let msg_key = decrypt_msg_key(&cyphertext[56..], &kkey, &nonce)?;

    let boxed_msg = &cyphertext[(56 + BOXED_KEY_SIZE_BYTES * msg_key.recp_count as usize)..];
    let mut out = vec![0; boxed_msg.len() - Hmac::SIZE];
    if msg_key.key.open_attached_into(&boxed_msg, &nonce, &mut out) {
        Some(out)
    } else {
        None
    }
}

fn decrypt_msg_key(boxes: &[u8], key: &Key, nonce: &Nonce) -> Option<MsgKey> {
    let mut msg_key = MsgKey::zeroed();
    for b in boxes
        .chunks_exact(BOXED_KEY_SIZE_BYTES)
        .take(MAX_RECIPIENTS)
    {
        if key.open_attached_into(b, &nonce, msg_key.as_bytes_mut()) {
            return Some(msg_key);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::*;
    use base64::decode;
    use serde_json;

    use std::error::Error;
    use std::fs::File;
    use std::path::Path;

    use ssb_crypto::Keypair;

    #[derive(Serialize, Deserialize)]
    struct Key {
        secret: String,
        public: String,
    }

    #[derive(Serialize, Deserialize)]
    struct TestData {
        cypher_text: String,
        msg: String,
        keys: Vec<Key>,
    }

    fn read_test_data_from_file<P: AsRef<Path>>(path: P) -> Result<TestData, Box<dyn Error>> {
        let file = File::open(path)?;
        let t = serde_json::from_reader(file)?;
        Ok(t)
    }

    #[test]
    fn simple() {
        let msg: [u8; 3] = [0, 1, 2];

        // init();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let recps = [alice.public, bob.public];
        let cypher = encrypt(&msg, &recps);

        let alice_result = decrypt(&cypher, &alice.secret);
        let bob_result = decrypt(&cypher, &bob.secret);

        assert_eq!(alice_result.unwrap(), msg);
        assert_eq!(bob_result.unwrap(), msg);
    }

    #[test]
    fn is_js_compatible() {
        let test_data = read_test_data_from_file("./test/simple.json").unwrap();

        let cypher = decode(&test_data.cypher_text).unwrap();
        let keys: Vec<Keypair> = test_data
            .keys
            .iter()
            .map(|key| Keypair::from_base64(&key.secret).unwrap())
            .collect();

        let alice = &keys[0];
        let bob = &keys[1];

        // init();
        assert_eq!(
            decrypt(&cypher, &alice.secret).unwrap(),
            test_data.msg.as_bytes()
        );
        assert_eq!(
            decrypt(&cypher, &bob.secret).unwrap(),
            test_data.msg.as_bytes()
        );
    }
    #[test]
    #[should_panic]
    fn passing_too_many_recipients_panics() {
        let msg: [u8; 3] = [0, 1, 2];

        // init();
        let alice = Keypair::generate();
        let recps = vec![alice.public; 33];
        let _ = encrypt(&msg, &recps);
    }
    #[test]
    #[should_panic]
    fn passing_zero_recipients_panics() {
        let msg: [u8; 3] = [0, 1, 2];

        // init();

        let recps: [PublicKey; 0] = [];
        let _ = encrypt(&msg, &recps);
    }
}
