//! Transfer-session input from clients: DH public keys and encrypted
//! secrets. Never panics; what the service encrypts it can decrypt.
#![no_main]

use libfuzzer_sys::fuzz_target;
use scopevault::service_api::transfer::{Algorithm, DH_AES, PLAIN, negotiate};
use zbus::zvariant::Value;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else { return };
    match selector % 3 {
        0 => {
            // A client's DH public key.
            let _ = negotiate(DH_AES, &Value::from(rest.to_vec()));
            let _ = negotiate(PLAIN, &Value::from(rest.to_vec()));
        }
        1 => {
            // An encrypted secret: IV (parameters) and ciphertext.
            let split = rest.first().map_or(0, |&b| usize::from(b) % 33).min(rest.len());
            let (params, value) = rest.split_at(split);
            let algorithm = Algorithm::DhAes(Zeroizing::new([7u8; 16]));
            let _ = algorithm.decrypt(params, value);
            let _ = Algorithm::Plain.decrypt(params, value);
        }
        _ => {
            for algorithm in [Algorithm::Plain, Algorithm::DhAes(Zeroizing::new([9u8; 16]))] {
                let (params, value) = algorithm.encrypt(rest).unwrap();
                assert_eq!(&*algorithm.decrypt(&params, &value).unwrap(), rest);
            }
        }
    }
});
