use std::{collections::HashMap, fs};

use openssl::symm::{decrypt, Cipher};

use base64::{engine::general_purpose, Engine};

fn hex_to_base64(hex: String) -> String {
    let bytes = hex_decode(hex);
    base64_encode(bytes)
}

fn hex_decode(hex: String) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn hex_encode(bytes: Vec<u8>) -> String {
    hex::encode(bytes)
}

fn base64_encode(bytes: Vec<u8>) -> String {
    general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn base64_decode(b64: String) -> Vec<u8> {
    general_purpose::STANDARD.decode(b64).unwrap()
}

fn fixed_xor(d1: Vec<u8>, d2: Vec<u8>) -> Vec<u8> {
    assert_eq!(d1.len(), d2.len());
    let mut res: Vec<u8> = Vec::with_capacity(d1.len());

    for i in 0..d1.len() {
        res.push(d1[i] ^ d2[i]);
    }

    res
}

fn xor_by_key(mut data: Vec<u8>, key: u8) -> Vec<u8> {
    for b in data.iter_mut() {
        *b = *b ^ key;
    }
    data
}

fn gen_frequency_map() -> HashMap<char, f64> {
    let mut res = HashMap::new();
    let data = fs::read_to_string("src/howlsmovingcastle.txt").unwrap();

    for c in data.chars() {
        if res.get_mut(&c).is_none() {
            res.insert(c, 0.0);
        }
        let val = res.get_mut(&c).unwrap();
        *val = *val + 1.0;
    }

    for (_k, v) in res.iter_mut() {
        *v = *v / data.len() as f64;
    }

    res
}

fn xor_brute_force(data: Vec<u8>) -> (String, u8) {
    let frequencies = gen_frequency_map();
    let mut best_score = 0.0;
    let mut plaintext = String::new();
    let mut best_key = 0;
    for key in 0..=255 {
        let decrypted = xor_by_key(data.clone(), key);
        match String::from_utf8(decrypted) {
            Ok(s) => {
                let current_score = score_text(&s, &frequencies);
                if current_score > best_score {
                    best_score = current_score;
                    plaintext = s;
                    best_key = key;
                }
            }
            Err(_) => continue,
        }
    }
    (plaintext, best_key)
}

fn score_text(input: &String, frequencies: &HashMap<char, f64>) -> f64 {
    let mut score: f64 = 0.0;
    for c in input.chars() {
        score += frequencies.get(&c).unwrap_or(&0.0);
    }
    score / input.len() as f64
}

fn repeating_key_xor(mut input: Vec<u8>, key: &[u8]) -> Vec<u8> {
    for i in 0..input.len() {
        input[i] = input[i] ^ key[i % key.len()];
    }

    input
}

fn hamming_distance(input1: &[u8], input2: &[u8]) -> usize {
    assert_eq!(input1.len(), input2.len());

    let mut difference = 0;

    for i in 0..input1.len() {
        let b = input1[i] ^ input2[i];
        difference += b.count_ones() as usize;
    }

    difference
}

fn xor_multibyte_bruteforce(input: Vec<u8>) -> (String, Vec<u8>) {
    let mut best_keysize = 2;
    // TODO this is scuffed as hell
    let mut best_distance = 999999.0;
    let mut keysizes: Vec<(usize, f64)> = Vec::new();

    // determine keysize
    for keysize in 2..=40 {
        let chunks: Vec<&[u8]> = input.chunks(keysize).take(4).collect();

        let mut distance = 0.0;

        for i in 0..4 {
            for j in i..4 {
                if i != j {
                    distance += hamming_distance(chunks[i], chunks[j]) as f64;
                }
            }
        }

        distance = distance / keysize as f64;

        keysizes.push((keysize, distance));

        if distance < best_distance {
            best_distance = distance;
            best_keysize = keysize;
        }
    }

    keysizes.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    println!("Keysizes: {:?}", keysizes);

    let mut outer: Vec<Vec<u8>> = Vec::with_capacity(input.len() / best_keysize);
    for _ in 0..best_keysize {
        outer.push(Vec::with_capacity(best_keysize));
    }

    assert_eq!(best_keysize, outer.len());

    println!("Input: {:?}", &input[0..20]);

    println!("Using this keysize: {best_keysize}");

    // transpose
    for i in 0..best_keysize {
        let mut j: usize = 0;
        while j < input.len() {
            if i + j < input.len() {
                outer[i].push(input[i + j]);
            }
            j += best_keysize;
        }
    }

    let mut keyvec = Vec::with_capacity(best_keysize);
    for v in outer {
        let (_plaintext, key) = xor_brute_force(v.clone());
        keyvec.push(key);
    }

    let output = repeating_key_xor(input, keyvec.as_slice());
    (String::from_utf8(output).unwrap(), keyvec)
}

fn decrypt_aes_ecb(data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, data.as_slice()).unwrap()
}

fn detect_aes_ecb(inputs: Vec<Vec<u8>>) -> usize {
    let mut least_different_idx = 0;
    let mut lowest_score = 99999;

    let get_score = |x: Vec<u8>| {
        let mut score = 0;
        let chunks: Vec<&[u8]> = x.chunks(16).collect();

        for i in 0..chunks.len() {
            for j in 0..chunks.len() {
                if i != j {
                    score += hamming_distance(chunks[i], chunks[j]);
                }
            }
        }

        score
    };

    for i in 0..inputs.len() {
        let input = inputs[i].clone();

        let score = get_score(input);

        println!("Score for {i}: {score}");

        if score < lowest_score {
            lowest_score = score;
            least_different_idx = i;
        }
    }

    least_different_idx
}

#[cfg(test)]
mod tests {

    use std::fs;

    use super::{
        base64_decode, decrypt_aes_ecb, detect_aes_ecb, fixed_xor, gen_frequency_map,
        hamming_distance, hex_decode, hex_encode, hex_to_base64, repeating_key_xor, score_text,
        xor_brute_force, xor_by_key, xor_multibyte_bruteforce,
    };

    #[test]
    fn challenge1() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(expected, hex_to_base64(String::from(hex)));
    }

    #[test]
    fn challenge2() {
        let d1 = hex_decode("1c0111001f010100061a024b53535009181c".to_owned());
        let d2 = hex_decode("686974207468652062756c6c277320657965".to_owned());
        let expected = "746865206b696420646f6e277420706c6179".to_owned();
        assert_eq!(expected, hex_encode(fixed_xor(d1, d2)));
    }

    #[test]
    fn challenge3() {
        let ciphertext = hex_decode(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_owned(),
        );
        let (plaintext, key) = xor_brute_force(ciphertext);
        assert_eq!(key, 88);
        assert_eq!(plaintext, "Cooking MC's like a pound of bacon".to_owned());
    }

    #[test]
    fn challenge4() {
        let input = fs::read_to_string("4.txt").unwrap();
        let mut overall_best_plaintext = String::new();
        let mut overall_best_score = 0.0;

        let frequencies = gen_frequency_map();

        for line in input.lines() {
            let bytes = hex_decode(line.to_owned());
            let mut best_score = 0.0;
            let mut best_key: u8 = 0;
            let mut best_plaintext = String::new();

            for key in 0..=255 {
                let decrypted = xor_by_key(bytes.clone(), key);
                match String::from_utf8(decrypted) {
                    Ok(s) => {
                        let current_score = score_text(&s, &frequencies);
                        if current_score > best_score {
                            best_score = current_score;
                            best_plaintext = s;
                            best_key = key;
                        }
                    }
                    Err(_) => continue,
                }
            }
            if best_score > overall_best_score {
                overall_best_score = best_score;
                overall_best_plaintext = best_plaintext;
            }
            best_score = 0.0;
        }

        let expected = String::from("Now that the party is jumping\n");

        assert_eq!(expected, overall_best_plaintext);
    }

    #[test]
    fn challenge5() {
        let plaintext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".to_vec();
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".to_owned();

        assert_eq!(expected, hex_encode(repeating_key_xor(plaintext, b"ICE")));
    }

    #[test]
    fn challenge6() {
        let input1 = b"this is a test";
        let input2 = b"wokka wokka!!!";
        assert_eq!(37, hamming_distance(input1, input2));

        let input = base64_decode(fs::read_to_string("6.txt").unwrap().replace("\n", ""));
        let output: (String, Vec<u8>) = xor_multibyte_bruteforce(input);

        let expected_key = b"Terminator X: Bring the noise";
        assert_eq!(expected_key, output.1.as_slice());
    }

    #[test]
    fn challenge7() {
        let input = base64_decode(fs::read_to_string("7.txt").unwrap().replace("\n", ""));

        let key = b"YELLOW SUBMARINE";

        let decrypted = decrypt_aes_ecb(input, key);
        let expected = "I'm back and I'm ringin' the bell";

        assert_eq!(expected, &String::from_utf8(decrypted).unwrap()[..33]);
    }

    #[test]
    fn challenge8() {
        let input: Vec<Vec<u8>> = fs::read_to_string("8.txt")
            .unwrap()
            .lines()
            .map(|x| hex_decode(String::from(x)))
            .collect();

        assert_eq!(132, detect_aes_ecb(input));
    }
}
