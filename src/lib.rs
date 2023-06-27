use wasm_bindgen::prelude::*;
use pbkdf2::{pbkdf2_hmac_array};
use sha2::Sha256;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
pub mod plain;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
    pub fn prompt(s: &str) -> String;
}

#[wasm_bindgen]
pub fn greet(_name: &str) -> String {
    let passwd = prompt(&format!("王荣达的手机号"));

    let mut buf = [0u8; 48];
    let key = passwd2key(&passwd);
    let iv = [0x24; 16];

    let ciphertext =  [ 0x34, 0xdc, 0x40, 0x1e, 0xae, 0xc7, 0xca, 0x5, 0x6a, 0x12, 0xc5, 0x41, 0xc6, 0x89, 0xd2, 0xe9, 0xd5, 0xde, 0xa, 0xfe, 0x25, 0x9a, 0x75, 0xfd, 0xc, 0x48, 0x20, 0x7c, 0x53, 0x98, 0x62, 0x27 ];
    let pt = Aes128CbcDec::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(&ciphertext, &mut buf)
        .unwrap();

    std::str::from_utf8(pt).unwrap().to_owned()
}

fn passwd2key(passwd: &str) -> [u8; 16] {
    let password = passwd.as_bytes();
    let salt = b"mys4s.cn";
    // number of iterations
    pbkdf2_hmac_array::<Sha256, 16>(password, salt, 4096)
}


// use hex_literal::hex;
// pub fn aes256cbc() {
//     let key = [0x42; 16];
//     let iv = [0x24; 16];
//     let plaintext = *b"hello world! this is my plaintext.";
//     let ciphertext = hex!(
//         "c7fe247ef97b21f07cbdd26cb5d346bf"
//         "d27867cb00d9486723e159978fb9a5f9"
//         "14cfb228a710de4171e396e7b6cf859e"
//     );

//     // encrypt/decrypt in-place
//     // buffer must be big enough for padded plaintext
//     let mut buf = [0u8; 48];
//     let pt_len = plaintext.len();
//     buf[..pt_len].copy_from_slice(&plaintext);
//     let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
//         .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
//         .unwrap();
//     assert_eq!(ct, &ciphertext[..]);

//     let pt = Aes128CbcDec::new(&key.into(), &iv.into())
//         .decrypt_padded_mut::<Pkcs7>(&mut buf)
//         .unwrap();
//     assert_eq!(pt, &plaintext);

//     // encrypt/decrypt from buffer to buffer
//     let mut buf = [0u8; 48];
//     let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
//         .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
//         .unwrap();
//     assert_eq!(ct, &ciphertext[..]);

//     let mut buf = [0u8; 48];
//     let pt = Aes128CbcDec::new(&key.into(), &iv.into())
//         .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
//         .unwrap();
//     assert_eq!(pt, &plaintext);

// }

#[cfg(test)]
mod test {
    use crate::plain;
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use pbkdf2::{pbkdf2_hmac_array};
    use sha2::Sha256;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    fn get_ciphertext() {
        let mut buf = [0u8; 1 << 16];
        let plaintext = plain::plaintext();
        let pt_len = plaintext.len();
        buf[..pt_len].copy_from_slice(plaintext.as_bytes());

        let passwd = plain::passwd();
        let salt = plain::salt();
        let key = pbkdf2_hmac_array::<Sha256, 16>(passwd.as_bytes(), salt.as_bytes(), 4096);
        let iv = [0x24; 16];
        let ct = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext.as_bytes(), &mut buf)
            .unwrap();
        println!("{:#02x?}", ct);
    }

    #[test]
    fn cipher() {
        get_ciphertext()
    }
    #[test]
    fn plain() {
        let mut buf = [0u8; 48];
        let key = crate::passwd2key("15988152673");
        let iv = [0x24; 16];

        let ciphertext =  [ 0x34, 0xdc, 0x40, 0x1e, 0xae, 0xc7, 0xca, 0x5, 0x6a, 0x12, 0xc5, 0x41, 0xc6, 0x89, 0xd2, 0xe9, 0xd5, 0xde, 0xa, 0xfe, 0x25, 0x9a, 0x75, 0xfd, 0xc, 0x48, 0x20, 0x7c, 0x53, 0x98, 0x62, 0x27 ];
        let pt = Aes128CbcDec::new(&key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(&ciphertext, &mut buf)
            .unwrap();
        println!("{}", std::str::from_utf8(pt).unwrap());
    }
}
