use libsodium_sys::{
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


const MAX_RECIPIENTS : usize = 7;
const NONCE_NUM_BYTES: usize = 24;
const KEY_NUM_BYTES: usize = 32;
const _KEY_NUM_BYTES: usize = KEY_NUM_BYTES + 1;


pub fn encrypt(plaintext: & [u8], recipients: &[[u8; 32]]) -> Vec<u8>{

    let mut nonce : [u8; NONCE_NUM_BYTES] = [0; NONCE_NUM_BYTES]; 
    let mut key : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES]; 
    let mut one_time_pubkey : [u8; crypto_box_PUBLICKEYBYTES ] = [0; crypto_box_PUBLICKEYBYTES]; 
    let mut one_time_secretkey : [u8; crypto_box_SECRETKEYBYTES ] = [0; crypto_box_SECRETKEYBYTES]; 
    unsafe {
        randombytes_buf(nonce.as_mut_ptr(), NONCE_NUM_BYTES);
        randombytes_buf(key.as_mut_ptr(), KEY_NUM_BYTES);
        crypto_box_keypair(& mut one_time_pubkey, & mut one_time_secretkey);
    }

    let mut _key : Vec<u8> = vec![(recipients.len() as u8 & MAX_RECIPIENTS as u8)];
    _key.extend_from_slice(&key.clone());

    let boxed_key_for_recipients : Vec<u8> = recipients
        .iter()
        .flat_map(|recipient|{
            let mut cyphertext : Vec<u8> = vec![0; _KEY_NUM_BYTES + crypto_secretbox_MACBYTES];

            let mut skey : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES];
            unsafe{
                crypto_scalarmult(& mut skey, & one_time_secretkey, recipient);
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

    let mut result : Vec<u8> = vec![]; 
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

pub fn decrypt(cyphertext: & [u8], secret_key: &[u8; 32]) -> Option<Vec<u8>>{
    let nonce = array_ref![cyphertext, 0, 24];
    let onetime_pk = array_ref![cyphertext, 24, 32];
    let mut my_key : [u8; KEY_NUM_BYTES] = [0; KEY_NUM_BYTES];

    let mut _key : [u8; _KEY_NUM_BYTES] = [0; _KEY_NUM_BYTES];
    let mut key : &[u8; KEY_NUM_BYTES] = &[1; 32];

    let mut num_recps = 0;
    let mut unbox_code = -1;

    unsafe{
        crypto_scalarmult(& mut my_key, secret_key, onetime_pk);
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
            key = array_ref![_key, 1, KEY_NUM_BYTES];
            break;
        }
    }

    match unbox_code {
        0 =>  {   
            let offset = START_BYTE_NUM + BOXED_KEY_SIZE_BYTES * num_recps as usize;
            let boxed_msg_len = cyphertext.len() - offset;
            let mut result = vec![0; boxed_msg_len - crypto_secretbox_MACBYTES ];

            unsafe{
                crypto_secretbox_open_easy(result.as_mut_ptr(), &cyphertext[offset], boxed_msg_len as u64, nonce, key);
            }
            Some(result) 
        },
        _ => None,
    }
} 

#[cfg(test)]
mod tests {
    use libsodium_sys::{
        sodium_init,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
        crypto_box_keypair,
    };
    use private_box::{encrypt, decrypt};
    #[test]
    fn simple() {
        let msg : [u8; 3] = [0,1,2];
        let mut alice_pk : [u8; crypto_box_PUBLICKEYBYTES] = [0; crypto_box_PUBLICKEYBYTES]; 
        let mut alice_sk : [u8; crypto_box_SECRETKEYBYTES] = [0; crypto_box_SECRETKEYBYTES]; 
        let mut bob_pk : [u8; crypto_box_PUBLICKEYBYTES] = [0; crypto_box_PUBLICKEYBYTES]; 
        let mut bob_sk : [u8; crypto_box_SECRETKEYBYTES] = [0; crypto_box_SECRETKEYBYTES]; 

        unsafe {
            sodium_init();
            crypto_box_keypair(& mut alice_pk, & mut alice_sk);
            crypto_box_keypair(& mut bob_pk, & mut bob_sk);
        }

        let recps: [[u8; 32]; 2] = [alice_pk, bob_pk];
        let cypher = encrypt(&msg, &recps);

        let alice_result = decrypt(&cypher, &alice_sk);
        let bob_result = decrypt(&cypher, &bob_sk);

        assert_eq!(alice_result.unwrap(), msg);
        assert_eq!(bob_result.unwrap(), msg);
    }
}
