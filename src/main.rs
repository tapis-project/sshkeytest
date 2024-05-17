use ssh_key::{Algorithm, HashAlg, EcdsaCurve, PrivateKey};
use rand_core::CryptoRngCore; // rand is implicitly exposed
use std::{ops::Deref, time::Instant};

/** This program records the time it takes to generate SSH keys using the different 
 * algorithms supported by the ssh-key crate.  Details about the options set for 
 * each algorithm can be discovered by drilling down into the source code of
 * PrivateKey::random() in the gen_ssh_keys() function.
 * 
 * The general result
 * 
 */
fn main() {
    // ****** CONFIGURE THESE PARAMETERS FOR EACH RUN ****** 
    const RSA_ITERATIONS: u32 = 100;
    const ITERATIONS: u32 = 10000;
    #[allow(non_snake_case)]
    let TEST_ALGS = ["RSA", "ECDSA", "ED25519"];  // valid options: ["RSA", "ECDSA", "ED25519"]
    // ****** END OF PARAMETER CONFIGURATION ****** 
    
    // Operating system's random number generator.
    let mut rng = rand::rngs::OsRng;
    // Secure thread-safe PRNG. See rand_chacha and ThreadRng for more info. 
    // let mut rng = rand::thread_rng(); // chacha prng

    // ------- Ecdsa 
    if TEST_ALGS.contains(&"ECDSA") {
        let curve = EcdsaCurve::NistP521;
        let start = Instant::now();
        gen_ssh_keys(ITERATIONS, &mut rng, Algorithm::Ecdsa {curve});
        let duration = start.elapsed();
        println!("Time to generate {} {} keys: {:?} ({:?} per key)", ITERATIONS, 
                (Algorithm::Ecdsa {curve}.to_string()), duration, duration/ITERATIONS);
    }

    // ------- Ed25519 
    if TEST_ALGS.contains(&"ED25519") {
        let start = Instant::now();
        gen_ssh_keys(ITERATIONS, &mut rng, Algorithm::Ed25519);
        let duration = start.elapsed();
        println!("Time to generate {} {} keys: {:?} ({:?} per key)", ITERATIONS, 
                (Algorithm::Ed25519.to_string()), duration, duration/ITERATIONS);
    }
    
    // ------- RSA 
    if TEST_ALGS.contains(&"RSA") {
        let hash = Some(HashAlg::Sha256);
        let start = Instant::now();
        gen_ssh_keys(RSA_ITERATIONS, &mut rng, Algorithm::Rsa {hash});
        let duration = start.elapsed();
        println!("Time to generate {} {} keys: {:?} ({:?} per key)", RSA_ITERATIONS, 
                (Algorithm::Rsa {hash}.to_string()), duration, duration/RSA_ITERATIONS);
    }
}

#[allow(unused_variables)]
fn gen_ssh_keys(iterations: u32, rng: &mut impl CryptoRngCore, algorithm: Algorithm) {
    // Announce this test.
    println!(">>>>>>>>>> Beginning test of {} iterations of {} keys.", iterations, algorithm.to_string());

    // Create keys in a loop.
    let mut key_cnt = 0;
    while key_cnt < iterations {
        // Increment key counter.
        key_cnt += 1;

        let alg = algorithm.clone();
        let key = match PrivateKey::random(rng, alg) {
            Ok(k) => k,
            Err(e) => {
                panic!("Key generation failed: {}", e);
            }
        };

        // Print first key.
        if key_cnt == 1 {
            // if let Ok(k) = key.to_openssh(ssh_key::LineEnding::LF) {
            //     println!("First key: \n{}", k.to_string());
            // }

            if let Ok(b) = key.to_bytes() {
                let v = b.deref();
                println!("Key length in bytes = {}", v.len());
            }
        }
    }
}
