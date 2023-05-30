use openssl::symm::{decrypt, Cipher};

fn pkcs7_padding(mut input: Vec<u8>) -> Vec<u8> {
    let count = 20 - input.len();
    for _ in 0..count {
        input.push(count as u8);
    }
    input
}

fn decrypt_aes_ecb(data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, data.as_slice()).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge1() {
        let input = b"YELLOW SUBMARINE".to_vec();
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
        let actual = pkcs7_padding(input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn challenge2() {
    }
}
