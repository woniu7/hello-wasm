use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn aes256cbc() {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use hex_literal::hex;

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let key = [0x42; 16];
    let iv = [0x24; 16];
    let plaintext = *b"hello world! this is my plaintext.";
    let ciphertext = hex!(
        "c7fe247ef97b21f07cbdd26cb5d346bf"
        "d27867cb00d9486723e159978fb9a5f9"
        "14cfb228a710de4171e396e7b6cf859e"
    );

    // encrypt/decrypt in-place
    // buffer must be big enough for padded plaintext
    let mut buf = [0u8; 48];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(&plaintext);
    let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    assert_eq!(ct, &ciphertext[..]);

    let pt = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap();
    assert_eq!(pt, &plaintext);

    // encrypt/decrypt from buffer to buffer
    let mut buf = [0u8; 48];
    let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
        .unwrap();
    assert_eq!(ct, &ciphertext[..]);

    let mut buf = [0u8; 48];
    let pt = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
        .unwrap();
    assert_eq!(pt, &plaintext);


    use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
    use sha2::Sha256;

    let password = b"password";
    let salt = b"salt";
    // number of iterations
    let n = 4096;
    // Expected value of generated key
    let expected = hex!("c5e478d59288c841aa530db6845c4c8d962893a0");

    let mut key1 = [0u8; 20];
    pbkdf2_hmac::<Sha256>(password, salt, n, &mut key1);
    assert_eq!(key1, expected);

    let key2 = pbkdf2_hmac_array::<Sha256, 20>(password, salt, n);
    assert_eq!(key2, expected);
}

#[cfg(test)]
mod test {
    use crate::aes256cbc;

    #[test]
    fn it_work() {
        println!("hello world");
        aes256cbc();
    }
}