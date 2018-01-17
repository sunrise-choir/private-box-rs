use libsodium_sys::{
    sodium_init,
    randombytes_buf, 
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_keypair,
    crypto_scalarmult,
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_secretbox_MACBYTES,
    sodium_memzero,
};

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{PublicKey, PUBLICKEYBYTES, SecretKey, SECRETKEYBYTES};
use std::cmp;

const MAX_RECIPIENTS : usize = 7;
const NONCE_NUM_BYTES: usize = 24;
const KEY_NUM_BYTES: usize = 32;
const _KEY_NUM_BYTES: usize = KEY_NUM_BYTES + 1;

/// libsodium must be initialised before calling `encrypt` or `decrypt`.
/// If you're using other libsodium based libraries that already initialise libsodium, you can omit
/// the call to `init`.
/// `init` is provided as a convenience function and the code is only:
/// ```
///pub fn init(){
///    unsafe{
///        sodium_init();
///    }
///}
/// ```
pub fn init(){
    unsafe{
        sodium_init();
    }
}

///Takes the message you want to encrypt, and an array of recipient public keys. Returns a message that is encrypted to all recipients and openable by them with `private_box::decrypt`. The number of recipients must be between 1 and 7.
///
///The encrypted length will be 56 + (recipients.length * 33) + plaintext.length bytes long, between 89 and 287 bytes longer than the plaintext.
///
///# Example
///```
///extern crate private_box;
///extern crate sodiumoxide;
///
///use private_box::{init, encrypt, decrypt};
///use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair;
///fn main() {
///    let msg : [u8; 3] = [0,1,2];
///
///    init();
///    let (alice_pk, alice_sk) = gen_keypair();
///    let (bob_pk, bob_sk) = gen_keypair();
///
///    let recps = [alice_pk, bob_pk];
///    let cypher = encrypt(&msg, &recps);
///
///    let alice_result = decrypt(&cypher, &alice_sk);
///    let bob_result = decrypt(&cypher, &bob_sk);
///
///    assert_eq!(alice_result.unwrap(), msg);
///    assert_eq!(bob_result.unwrap(), msg);
///}
///```
pub fn encrypt(plaintext: & [u8], recipients: &[PublicKey]) -> Vec<u8>{

    let mut nonce : [u8; NONCE_NUM_BYTES] = [0; NONCE_NUM_BYTES]; 
    let mut key : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES]; 
    let mut one_time_pubkey : [u8; crypto_box_PUBLICKEYBYTES ] = [0; crypto_box_PUBLICKEYBYTES]; 
    let mut one_time_secretkey : [u8; crypto_box_SECRETKEYBYTES ] = [0; crypto_box_SECRETKEYBYTES]; 
    unsafe {
        randombytes_buf(nonce.as_mut_ptr(), NONCE_NUM_BYTES);
        randombytes_buf(key.as_mut_ptr(), KEY_NUM_BYTES);
        crypto_box_keypair(& mut one_time_pubkey, & mut one_time_secretkey);
    }

    let mut _key : Vec<u8> = vec![cmp::min(recipients.len() as u8, MAX_RECIPIENTS as u8)];
    _key.extend_from_slice(&key.clone());

    let boxed_key_for_recipients : Vec<u8> = recipients
        .iter()
        .flat_map(|recipient|{
            let mut cyphertext : Vec<u8> = vec![0; _KEY_NUM_BYTES + crypto_secretbox_MACBYTES];
            let recipient_bytes = array_ref![recipient.as_ref(), 0, PUBLICKEYBYTES];

            let mut skey : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES];
            unsafe{
                crypto_scalarmult(& mut skey, & one_time_secretkey, recipient_bytes);
                crypto_secretbox_easy(cyphertext.as_mut_ptr(), _key.as_ptr(), _key.len() as u64, &nonce, &skey);
                sodium_memzero(skey.as_mut_ptr(), skey.len());
            }
            cyphertext
        })
        .collect::<Vec<u8>>();

    let mut boxed_message : Vec<u8> = vec![0; plaintext.len() + crypto_secretbox_MACBYTES];

    unsafe{
        crypto_secretbox_easy(boxed_message.as_mut_ptr(), plaintext.as_ptr(), plaintext.len() as u64, &nonce, &key);
    }

    let mut result : Vec<u8> = Vec::with_capacity(NONCE_NUM_BYTES + KEY_NUM_BYTES + boxed_key_for_recipients.len() + boxed_message.len()); 
    result.extend_from_slice(&nonce.clone());
    result.extend_from_slice(&one_time_pubkey);
    result.extend(boxed_key_for_recipients);
    result.extend(boxed_message);

    unsafe{
        sodium_memzero(one_time_secretkey.as_mut_ptr(), crypto_box_SECRETKEYBYTES);
        sodium_memzero(one_time_pubkey.as_mut_ptr(), crypto_box_PUBLICKEYBYTES);
        sodium_memzero(key.as_mut_ptr(), KEY_NUM_BYTES);
        sodium_memzero(nonce.as_mut_ptr(), NONCE_NUM_BYTES);
        sodium_memzero(_key.as_mut_ptr(), _KEY_NUM_BYTES);
    }

    result
} 

const START_BYTE_NUM : usize = 24 + 32;
const BOXED_KEY_SIZE_BYTES : usize = 32 + 1 + 16;

///Attempt to decrypt a private-box message, using your secret key. If you were an intended recipient then the decrypted message is returned as `Ok(Vec<u8>)`. If it was not for you, then `Err(())` will be returned.
///
///# Example
///```
///extern crate private_box;
///extern crate sodiumoxide;
///
///use private_box::{init, encrypt, decrypt};
///use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair;
///fn main() {
///    let msg : [u8; 3] = [0,1,2];
///
///    init();
///    let (alice_pk, alice_sk) = gen_keypair();
///    let (bob_pk, bob_sk) = gen_keypair();
///
///    let recps = [alice_pk, bob_pk];
///    let cypher = encrypt(&msg, &recps);
///
///    let alice_result = decrypt(&cypher, &alice_sk);
///    let bob_result = decrypt(&cypher, &bob_sk);
///
///    assert_eq!(alice_result.unwrap(), msg);
///    assert_eq!(bob_result.unwrap(), msg);
///}
///
///```
pub fn decrypt(cyphertext: & [u8], secret_key: &SecretKey) -> Result<Vec<u8>, ()>{
    let nonce = array_ref![cyphertext, 0, 24];
    let onetime_pk = array_ref![cyphertext, 24, 32];
    let secret_key_bytes = array_ref![secret_key[..], 0, SECRETKEYBYTES];
    let mut my_key : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES];

    let mut _key : [u8; _KEY_NUM_BYTES] = [0; _KEY_NUM_BYTES];
    let mut key : [u8; KEY_NUM_BYTES] = [0; 32];

    let mut num_recps = 0;
    let mut unbox_code;
    let mut did_unbox = false;

    unsafe{
        crypto_scalarmult(& mut my_key, secret_key_bytes, onetime_pk);
    }

    for i in 0..MAX_RECIPIENTS {
        let offset = START_BYTE_NUM + BOXED_KEY_SIZE_BYTES * i;
        if (offset + BOXED_KEY_SIZE_BYTES) > (cyphertext.len() - 16){
            break; 
        }
        let boxed_key_chunk = array_ref![cyphertext, offset, BOXED_KEY_SIZE_BYTES];

        unsafe {
            unbox_code = crypto_secretbox_open_easy(_key.as_mut_ptr(), boxed_key_chunk.as_ptr(), BOXED_KEY_SIZE_BYTES as u64, nonce, &my_key);
        }
        if unbox_code == 0 {
            num_recps = _key[0];
            key = array_ref![_key, 1, KEY_NUM_BYTES].clone();
            did_unbox = true;
            continue;
        }
    }

    match did_unbox {
        true =>  {   
            let offset = START_BYTE_NUM + BOXED_KEY_SIZE_BYTES * num_recps as usize;
            let boxed_msg_len = cyphertext.len() - offset;
            let mut result = vec![0; boxed_msg_len - crypto_secretbox_MACBYTES ];

            unsafe{
                crypto_secretbox_open_easy(result.as_mut_ptr(), &cyphertext[offset], boxed_msg_len as u64, nonce, &key);
            }
            Ok(result) 
        },
        false => Err(()),
    }
} 

#[cfg(test)]
mod tests {

    use private_box::{init, encrypt, decrypt};
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{PublicKey, SecretKey, SECRETKEYBYTES, PUBLICKEYBYTES, gen_keypair};
    use serde_json;

    use std::error::Error;
    use std::fs::File;
    use std::path::Path;

    use base64::decode;

    #[derive(Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct Key {
       secretKey: String,
       publicKey: String
    }

    #[derive(Serialize, Deserialize)]
    #[allow(non_snake_case)]
    struct TestData {
        cypherText : String,
        msg : String,
        keys: Vec<Key>,
    }

    fn read_test_data_from_file<P: AsRef<Path>>(path: P) -> Result<TestData, Box<Error>> {
        // Open the file in read-only mode.
        let file = File::open(path)?;

        // Read the JSON contents of the file as an instance of `User`.
        let u = serde_json::from_reader(file)?;

        // Return the `User`.
        Ok(u)
    }

    #[test]
    fn simple() {
        let msg : [u8; 3] = [0,1,2];

        init();
        let (alice_pk, alice_sk) = gen_keypair();
        let (bob_pk, bob_sk) = gen_keypair();

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
         
        let cypher = decode(&test_data.cypherText).unwrap();
        let msg = decode(&test_data.msg).unwrap();
        let keys : Vec<(PublicKey, SecretKey)> = test_data.keys
            .iter()
            .map(|key|{
                let mut pub_key : [u8; PUBLICKEYBYTES] = [0; 32];
                let mut sec_key : [u8; SECRETKEYBYTES] = [0; 32];
                pub_key.copy_from_slice(&decode(&key.publicKey).unwrap());
                sec_key.copy_from_slice(&decode(&key.secretKey).unwrap());
                    
                (PublicKey(pub_key), SecretKey(sec_key)) 
            })
            .collect();

        let (_, ref alice_sk) = keys[0];
        let (_, ref bob_sk) = keys[1];

        init();
        let alice_result = decrypt(&cypher, &alice_sk);
        let bob_result = decrypt(&cypher, &bob_sk);

        assert_eq!(alice_result.unwrap(), msg);
        assert_eq!(bob_result.unwrap(), msg);
    }
    //TODO: passing too many recipients errors.
    //TODO: can encrypt / decrypt up to 255 recips after setting a cutom max.
    //TODO: passing more than 255 or less than 1 errors.
}
