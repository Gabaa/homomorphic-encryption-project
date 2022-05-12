use rug::{ops::Pow, Integer};
use sha2::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::{
    encryption::{add, PublicKey},
    mpc::{decode, diag, encode, encrypt_det, Ciphertext, Parameters},
    poly::Polynomial,
    prob::{sample_from_uniform, sample_single},
};

use super::{SEC, V};

/// Make a zero-knowledge proof of plaintext knowledge
#[allow(clippy::needless_range_loop, clippy::type_complexity)]
pub fn make_zkpopk(
    params: &Parameters,
    x: Vec<Polynomial>,
    r: Vec<(Polynomial, Polynomial, Polynomial)>,
    c: Vec<Ciphertext>,
    diagonal: bool,
    pk: &PublicKey,
) -> (Vec<Vec<Polynomial>>, Vec<Vec<Integer>>, Vec<Vec<Integer>>) {
    let tau = &params.p / Integer::from(2_i32);
    let rho = Integer::from(2_i32)
        * Integer::from(params.r as i64)
        * Integer::sqrt(Integer::from(params.n));
    let d = params.n * 3;

    let y_i_bound =
        Integer::from(128_i32) * Integer::from(params.n) * tau * Integer::from(SEC).pow(2);
    let s_i_bound = Integer::from(128_i32) * Integer::from(d) * rho * Integer::from(SEC).pow(2);

    let mut y = Vec::with_capacity(V);
    let mut s = Vec::with_capacity(V);

    let mut a = Vec::with_capacity(V);
    for i in 0..V {
        let mut m_i = sample_single(&params.p);
        if diagonal {
            m_i = diag(params, m_i)
        }
        let encoded_m_i = encode(m_i);
        let u_i = sample_from_uniform(&((y_i_bound.clone() / params.p.clone()) - 1_i32), params.n)
            * params.p.clone();
        y.push(encoded_m_i + u_i);

        s.push((
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
            sample_from_uniform(&s_i_bound, params.n),
        ));

        a.push(encrypt_det(params, y[i].clone(), pk, s[i].clone()))
    }

    // Create a SEC-bit bitstring (each bit represented by u8)
    let e = hash(&a, &c);
    let m_e = create_m_e_from_e(e);

    // Calculate z (such that z^T = y^T + M_e * x^T)
    // z : Z^{n x V}
    // Note that we are creating a vector of columns, not a vector of rows.
    let mut z = Vec::with_capacity(V);
    for i in 0..V {
        let mut z_col = Vec::with_capacity(V);

        for j in 0..params.n {
            // Get y^T values
            let y_col = &y[i];
            let mut val = y_col.coefficient(j).to_owned();

            // Multiply M_e * x^T and add it
            for k in 0..SEC {
                let x_k = &x[k];
                val += m_e[k][i] * x_k.coefficient(j).to_owned();
            }

            z_col.push(val);
        }

        z.push(z_col);
    }

    // Create R matrix
    // This part makes me sad - the default state of any programmer.
    let mut r_mat = Vec::with_capacity(SEC);
    for (r1, r2, r3) in r.iter() {
        let mut row = Vec::with_capacity(d);

        for c in r1.coefficients() {
            row.push(c.to_owned());
        }
        while row.len() < params.n {
            row.push(Integer::ZERO)
        }

        for c in r2.coefficients() {
            row.push(c.to_owned());
        }
        while row.len() < params.n * 2 {
            row.push(Integer::ZERO)
        }

        for c in r3.coefficients() {
            row.push(c.to_owned());
        }
        while row.len() < params.n * 3 {
            row.push(Integer::ZERO)
        }

        r_mat.push(row);
    }

    // Calculate M_e * R
    let mut m_e_mul_r = vec![vec![Integer::ZERO; d]; V];
    for (row_index, row) in m_e_mul_r.iter_mut().enumerate() {
        for (col_index, val) in row.iter_mut().enumerate() {
            for i in 0..SEC {
                *val += m_e[i][row_index] * r_mat[i][col_index].clone()
            }
        }
    }

    // Calculate T = S + M_e * R
    let mut t = vec![vec![Integer::ZERO; d]; V];
    for (t_row_index, t_row) in t.iter_mut().enumerate() {
        let (s_row_1, s_row_2, s_row_3) = &s[t_row_index];
        let mut s_row = s_row_1
            .coefficients()
            .chain(s_row_2.coefficients())
            .chain(s_row_3.coefficients());

        for (t_col_index, t_val) in t_row.iter_mut().enumerate() {
            let s_val = s_row.next().unwrap().to_owned();
            let m_e_mul_r_val = &m_e_mul_r[t_row_index][t_col_index];

            *t_val = s_val + m_e_mul_r_val;
        }
    }

    (a, z, t)
}

/// Verify the validity of a zero-knowledge proof of plaintext knowledge
pub fn verify_zkpopk(
    params: &Parameters,
    a: Vec<Vec<Polynomial>>,
    z: Vec<Vec<Integer>>,
    t: Vec<Vec<Integer>>,
    c: Vec<Ciphertext>,
    pk: &PublicKey,
) -> bool {
    // encrypt d_i = enc_pk(z_i, t_i)
    let mut d = Vec::with_capacity(V);
    for i in 0..V {
        let (t_1, t_23) = t[i].split_at(params.n);
        let (t_2, t_3) = t_23.split_at(params.n);
        let t = (
            Polynomial::new(t_1.iter().map(|x| x.to_owned()).collect()),
            Polynomial::new(t_2.iter().map(|x| x.to_owned()).collect()),
            Polynomial::new(t_3.iter().map(|x| x.to_owned()).collect()),
        );

        d.push(encrypt_det(params, Polynomial::new(z[i].clone()), pk, t))
    }

    // creates the m_e matrix
    let e = hash(&a, &c);
    let m_e = create_m_e_from_e(e);

    // The verifier checks decode(z_i) \in f_{p_k}^s
    let mut decoded_z_is = Vec::with_capacity(V);
    for z_i in &z {
        decoded_z_is.push(decode(Polynomial::new(z_i.to_owned())));
    }
    if decoded_z_is.len() > V {
        println!("Length of zero knowledge proof is wrong");
        return false;
    }

    // Check d^t = a^t |+| (m_e |*| c^t)
    for i in 0..V {
        let mut sum = Ciphertext::new();
        for j in 0..SEC {
            if m_e[j][i] == 1 {
                sum = add(params, &sum, &c[j]);
            }
        }

        let test = add(params, &a[i], &sum);

        if test != d[i] {
            println!("There was a failure in the d_i test!");
            return false;
        }
    }

    // ||z_i||_{inf} <= 128 * N * t * sec^2
    let tau = &params.p / Integer::from(2_i32);
    for z_i in z {
        let z_i_inf_ok = Polynomial::new(z_i).l_inf_norm()
            <= Integer::from(128_i32) * Integer::from(params.n) * &tau * Integer::from(SEC.pow(2));

        if !z_i_inf_ok {
            println!("z_i_inf_norm was not ok!");
            return false;
        }
    }

    // ||t_i||_{inf} <= 128 * d * p * sec^2
    let rho = Integer::from(2_i32)
        * Integer::from(params.r as i64)
        * Integer::sqrt(Integer::from(params.n));
    let d = params.n * 3;
    for t_i in t {
        let t_i_inf_norm_ok = Polynomial::new(t_i).l_inf_norm()
            <= Integer::from(128_i32)
                * Integer::from(d)
                * Integer::from(&rho)
                * Integer::from(SEC.pow(2));
        if !t_i_inf_norm_ok {
            println!("t_i_inf_norm was not ok!");
            return false;
        }
    }
    // TODO: check if decode(z_i) is a diagonal argument if diag is set to true!

    true
}

/// Hash `(a, c)` to get a random value `e`
fn hash(a: &[Vec<Polynomial>], c: &[Vec<Polynomial>]) -> Vec<u8> {
    let mut hasher = Shake256::default();

    for ciphertext in a {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(p));
        }
    }
    for ciphertext in c {
        for p in ciphertext {
            hasher.update(&polynomial_to_bytes(p));
        }
    }

    let mut reader = hasher.finalize_xof();
    let mut e_bytes = [0_u8; SEC / 8];
    reader.read(&mut e_bytes);

    let mut e_bit_string = String::new();
    for e_byte in e_bytes {
        e_bit_string = format!("{}{:08b}", e_bit_string, &e_byte);
    }

    let mut e_bits = Vec::with_capacity(SEC);
    for c in e_bit_string.chars() {
        match c {
            '0' => e_bits.push(0),
            '1' => e_bits.push(1),
            _ => unreachable!("should only have 0's and 1's"),
        }
    }

    e_bits
}

/// A little hack to convert a polynomial to bytes
fn polynomial_to_bytes(p: &Polynomial) -> Vec<u8> {
    let json = serde_json::to_string(p).unwrap();
    json.as_bytes().to_owned()
}

fn create_m_e_from_e(e: Vec<u8>) -> Vec<Vec<u8>> {
    let mut m_e = vec![vec![0_u8; V]; SEC];
    for (i, row) in m_e.iter_mut().enumerate() {
        for (k, item) in row.iter_mut().enumerate() {
            let e_index = i as i32 - k as i32;

            if (0..(SEC as i32)).contains(&e_index) {
                *item = e[e_index as usize];
            }
        }
    }
    m_e
}

#[cfg(test)]
mod tests {
    use rug::{rand::RandState, Integer};

    use crate::{
        encryption::{
            self, encrypt_with_rand, generate_key_pair, Ciphertext, Parameters, PublicKey,
            SecretKey,
        },
        poly::Polynomial,
    };

    use super::{make_zkpopk, verify_zkpopk, SEC};

    #[allow(clippy::type_complexity)]
    fn setup(
        params: &Parameters,
    ) -> (
        PublicKey,
        SecretKey,
        Vec<Polynomial>,
        Vec<(Polynomial, Polynomial, Polynomial)>,
        Vec<Ciphertext>,
    ) {
        let (pk, sk) = generate_key_pair(params);

        let mut x = Vec::with_capacity(SEC);
        let mut r = Vec::with_capacity(SEC);
        let mut c = Vec::with_capacity(SEC);
        for _ in 0..SEC {
            let x_i = Polynomial::new(vec![random_integer()]).modulo(&params.p);
            let (c_i, r_i) = encrypt_with_rand(params, x_i.clone(), &pk);
            x.push(x_i);
            r.push(r_i);
            c.push(c_i);
        }

        (pk, sk, x, r, c)
    }

    fn random_integer() -> Integer {
        let mut rng = RandState::new();
        Integer::random_bits(256, &mut rng).into()
    }

    #[test]
    fn verify_accepts_valid_zkpopk() {
        let params = Parameters::default();
        let (pk, _sk, x, r, c) = setup(&params);

        let (a, z, t) = make_zkpopk(&params, x, r, c.clone(), false, &pk);

        assert!(
            verify_zkpopk(&params, a, z, t, c, &pk),
            "proof was not valid"
        )
    }

    #[test]
    fn verify_accepts_valid_zkpopk_with_secure_params() {
        let params = encryption::secure_params();
        let (pk, _sk, x, r, c) = setup(&params);

        let (a, z, t) = make_zkpopk(&params, x, r, c.clone(), false, &pk);

        assert!(
            verify_zkpopk(&params, a, z, t, c, &pk),
            "proof was not valid"
        )
    }

    #[test]
    fn verify_accepts_valid_zkpopk_diagonal() {
        let params = Parameters::default();
        let (pk, _sk, x, r, c) = setup(&params);

        let (a, z, t) = make_zkpopk(&params, x, r, c.clone(), true, &pk);

        assert!(
            verify_zkpopk(&params, a, z, t, c, &pk),
            "proof was not valid"
        )
    }
}
