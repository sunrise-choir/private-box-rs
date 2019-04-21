use ssb_crypto::{
    PublicKey,
    SecretKey,
};

// TODO: turns out these things are used for more than just the handshake,
// so the ssb_crypto submodule should probably be renamed.
use ssb_crypto::handshake::{
    derive_shared_secret_pk,
    derive_shared_secret_sk,
    EphPublicKey,
    generate_ephemeral_keypair,
};
use ssb_crypto::secretbox;
use ssb_crypto::utils::memzero;

const MAX_RECIPIENTS : usize = 32;

/// libsodium must be initialised before calling `encrypt` or `decrypt`.
/// If you're using other libsodium based libraries that already initialise libsodium, you can omit
/// the call to `init`.
pub fn init() {
    ssb_crypto::init();
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
/// use private_box::{init, encrypt, decrypt};
/// use ssb_crypto::generate_longterm_keypair;
///
/// fn main() {
///     init();
///     let msg = "hello!".as_bytes();
///
///     let (alice_pk, alice_sk) = generate_longterm_keypair();
///     let (bob_pk, bob_sk) = generate_longterm_keypair();
///
///     let recps = [alice_pk, bob_pk];
///     let cypher = encrypt(msg, &recps);
///
///     let alice_result = decrypt(&cypher, &alice_sk);
///     let bob_result = decrypt(&cypher, &bob_sk);
///
///     assert_eq!(alice_result.unwrap(), msg);
///     assert_eq!(bob_result.unwrap(), msg);
/// }
/// ```
pub fn encrypt(plaintext: &[u8], recipients: &[PublicKey]) -> Vec<u8> {

    if recipients.len() > MAX_RECIPIENTS || recipients.len() == 0 {
        panic!("Number of recipients must be less than {}, greater than 0", MAX_RECIPIENTS);
    }

    let nonce = secretbox::gen_nonce();
    let key = secretbox::gen_key();
    let (eph_pk, eph_sk) = generate_ephemeral_keypair();

    // The "key" that's encrypted for each recipient is 33 bytes:
    // the first byte is the number of recipients,
    // other 32 bytes are the secretbox key.
    let mut key_with_prefix = [0; 33];
    key_with_prefix[0] = recipients.len() as u8;
    key_with_prefix[1..].copy_from_slice(&key[..]);

    let boxed_key_for_recipients = recipients
        .iter()
        .flat_map(|recip_pk| {
            let secret = derive_shared_secret_pk(&eph_sk, recip_pk).unwrap(); // TODO: `as secretbox::Key`?

            let kkey = secretbox::Key::from_slice(&secret[..]).unwrap();
            secretbox::seal(&key_with_prefix[..], &nonce, &kkey)
        })
        .collect::<Vec<u8>>();

    let boxed_message = secretbox::seal(&plaintext, &nonce, &key);

    let mut result: Vec<u8> = Vec::with_capacity(nonce[..].len() + eph_pk[..].len() + boxed_key_for_recipients.len() + boxed_message.len());
    result.extend_from_slice(&nonce[..]);
    result.extend_from_slice(&eph_pk[..]);
    result.extend(boxed_key_for_recipients);
    result.extend(boxed_message);

    // The other keys are (or should be) memzeroed in their Drop impls.
    memzero(&mut key_with_prefix);

    result
}

const BOXED_KEY_SIZE_BYTES : usize = 32 + 1 + 16;

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
/// use private_box::{init, encrypt, decrypt};
/// use ssb_crypto::generate_longterm_keypair;
///
/// fn main() {
///     init();
///     let msg = "hello!".as_bytes();
///
///     let (alice_pk, alice_sk) = generate_longterm_keypair();
///     let (bob_pk, bob_sk) = generate_longterm_keypair();
///
///     let recps = [alice_pk, bob_pk];
///     let cypher = encrypt(msg, &recps);
///
///     let alice_result = decrypt(&cypher, &alice_sk);
///     let bob_result = decrypt(&cypher, &bob_sk);
///
///     assert_eq!(&alice_result.unwrap(), &msg);
///     assert_eq!(&bob_result.unwrap(), &msg);
/// }
///```
pub fn decrypt(cyphertext: &[u8], secret_key: &SecretKey) -> Option<Vec<u8>> {
    let nonce = secretbox::Nonce::from_slice(&cyphertext[0..24])?;
    let eph_pk = EphPublicKey::from_slice(&cyphertext[24..56])?;

    let secret = derive_shared_secret_sk(secret_key, &eph_pk)?;
    let kkey = secretbox::Key::from_slice(&secret[..])?;

    let key_with_prefix = cyphertext[56..]
        .chunks_exact(BOXED_KEY_SIZE_BYTES)
        .find_map(|buf| secretbox::open(&buf, &nonce, &kkey).ok())?;

    let num_recps = key_with_prefix[0] as usize;
    let key = secretbox::Key::from_slice(&key_with_prefix[1..])?;

    let boxed_msg = &cyphertext[(56 + BOXED_KEY_SIZE_BYTES * num_recps)..];
    secretbox::open(&boxed_msg, &nonce, &key).ok()
}

#[cfg(test)]
mod tests {
    use base64::decode;
    use crate::*;
    use serde_json;

    use std::error::Error;
    use std::fs::File;
    use std::path::Path;

    use ssb_crypto::{
        generate_longterm_keypair,
        PublicKey,
        SecretKey,

    };


    #[derive(Serialize, Deserialize)]
    struct Key {
       secret: String,
       public: String
    }

    #[derive(Serialize, Deserialize)]
    struct TestData {
        cypher_text: String,
        msg: String,
        keys: Vec<Key>,
    }

    fn read_test_data_from_file<P: AsRef<Path>>(path: P) -> Result<TestData, Box<Error>> {
        let file = File::open(path)?;
        let t = serde_json::from_reader(file)?;
        Ok(t)
    }

    #[test]
    fn simple() {
        let msg : [u8; 3] = [0,1,2];

        init();
        let (alice_pk, alice_sk) = generate_longterm_keypair();
        dbg!(alice_sk.0.len());
        let (bob_pk, bob_sk) = generate_longterm_keypair();

        let recps = [alice_pk, bob_pk];
        let cypher = encrypt(&msg, &recps);

        let alice_result = decrypt(&cypher, &alice_sk);
        let bob_result = decrypt(&cypher, &bob_sk);

        assert_eq!(alice_result.unwrap(), msg);
        assert_eq!(bob_result.unwrap(), msg);
    }

    #[test]
    fn is_js_compatible(){
        let test_data = read_test_data_from_file("./test/simple.json").unwrap();

        let cypher = decode(&test_data.cypher_text).unwrap();
        let keys : Vec<(PublicKey, SecretKey)> = test_data.keys
            .iter()
            .map(|key|{
                let pk = PublicKey::from_slice(&decode(&key.public).unwrap()).unwrap();
                let sk = SecretKey::from_slice(&decode(&key.secret).unwrap()).unwrap();
                (pk, sk)
            })
            .collect();

        let (_, ref alice_sk) = keys[0];
        let (_, ref bob_sk) = keys[1];

        init();
        let alice_result = decrypt(&cypher, &alice_sk);
        let bob_result = decrypt(&cypher, &bob_sk);

        assert_eq!(alice_result.unwrap(), test_data.msg.as_bytes());
        assert_eq!(bob_result.unwrap(), test_data.msg.as_bytes());
    }
    #[test]
    #[should_panic]
    fn passing_too_many_recipients_panics(){
        let msg : [u8; 3] = [0,1,2];

        init();
        let (alice_pk, _) = generate_longterm_keypair();
        let recps = vec![alice_pk; 33];
        let _ = encrypt(&msg, &recps);

    }
    #[test]
    #[should_panic]
    fn passing_zero_recipients_panics(){
        let msg : [u8; 3] = [0,1,2];

        init();

        let recps : [PublicKey; 0] = [];
        let _ = encrypt(&msg, &recps);
    }


}
