use homomorphic_encryption_project::{
    encryption::{self, Parameters},
    poly::Polynomial,
    polynomial,
};

fn main() {
    let params = Parameters::default();

    //Construct noisy params
    let noisy_params =
        Parameters::new::<i32>(65537, 2_u32.pow(2) as f64, 2_u32.pow(10) as f64, 4, 7);

    let (pk, sk) = encryption::generate_key_pair(&params);

    let msg_bob = polynomial![1];
    let msg_alice = polynomial![1];

    let encrypted_msg_bob = encryption::encrypt(&params, msg_bob, &pk);
    let encrypted_msg_alice = encryption::encrypt(&params, msg_alice, &pk);

    let encrypted_res = encryption::mul(&params, &encrypted_msg_bob, &encrypted_msg_alice);
    println!("{:?}", encrypted_res);

    let noisy_ciphertext = encryption::drown_noise(&params, &noisy_params, encrypted_res, pk);
    println!("{:?}", noisy_ciphertext);

    let decrypted_noisy = encryption::decrypt(&params, noisy_ciphertext, &sk);
    println!("{:?}", decrypted_noisy)
}
