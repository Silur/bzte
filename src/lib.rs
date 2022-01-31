use std::{fmt, ops::{Mul, Add, Sub, Div}, cmp::Ordering};
use ark_std::UniformRand;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_serialize::CanonicalSerialize;
use ark_ff::{Field, PrimeField, Zero, One, FromBytes};
use ark_bls12_381::{G1Projective as G1, G1Affine, G2Affine, G2Projective as G2, Fr};
use std::collections::hash_set::HashSet;
use sha2::Digest;

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

pub struct TPKEPublicKey {
    l: u64,
    k: u64,
    g1: G1,
    g2: G2,
    VK: G1,
    VKs: Vec<G1>,
}

pub struct TPKEPrivateKey {
    pk: TPKEPublicKey,
    sk: Fr,
}

pub struct TPKECipherText {
    U: G1,
    V: Vec<u8>,
    W: G2
}

#[derive(Debug)]
pub enum TPKEError {
    InvalidLength,
    InvalidValue,
}
impl std::error::Error for TPKEError {}
impl fmt::Display for TPKEError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TPKEError::InvalidLength => write!(f, "Invalid length"),
            TPKEError::InvalidValue => write!(f, "Invalid value"),
        }
    }
}
impl TPKEPublicKey {
    fn new(l: u64, k: u64, VK: G1, VKs: &[G1]) -> Self {
        let g1 = G1::from(G1Affine::from_random_bytes(&sha256(b"bzte-g1")).unwrap());
        let g2 = G2::from(G2Affine::from_random_bytes(&sha256(b"bzte-g2")).unwrap());

        Self {
            g1: g1,
            g2: g2,
            l: l,
            k: k,
            VK: VK,
            VKs: VKs.to_vec()
        }
    }

    fn lagrange(&self, indices: Vec<u64>, j: u64) -> Result<Fr, TPKEError> {
        if indices.len() != self.k as usize {
            return Err(TPKEError::InvalidLength);
        }
        let mut sorted = indices.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != indices.len() {
            return Err(TPKEError::InvalidValue);
        }
        let mut contains_j = false;
        for i in sorted.iter() {
            if *i == j { contains_j = true; }
            if i > &self.l {
                return Err(TPKEError::InvalidValue);
            }
        }
        if !contains_j {
            return Err(TPKEError::InvalidValue);
        }
        let num = sorted.iter().map(|x| { 
            match x.cmp(&j) {
                Ordering::Equal => Fr::from(1),
                _ => Fr::from(0).sub(Fr::from(*x as u128)).sub(Fr::from(1))
            }
        }).fold(Fr::from(1), |acc, x| {
            acc.mul(x)
        });

        let den = sorted.iter().map(|x| { 
            match x.cmp(&j) {
                Ordering::Equal => Fr::from(1),
                _ => Fr::from(j).sub(Fr::from(*x as u128))
            }
        }).fold(Fr::from(1), |acc, x| {
            acc.mul(x)
        });

        Ok(num.div(den))
    }
    fn encrypt(&self, m: &[u8]) -> Result<TPKECipherText, TPKEError> {
        if m.len() != 32 { return Err(TPKEError::InvalidLength); }
        let mut rng = rand::thread_rng();
        let r = Fr::rand(&mut rng).into_repr();
        let U = self.g1.mul(r);
        let VKr = self.VK.mul(r);
        let mut V = vec![0u8; 32];
        VKr.serialize(&mut V).expect("deserialize error");
        V = sha256(&V);
        for i in 0..32 {
            V[i] ^= m[i];
        }
        let W = hashH(U, &V).mul(r);
        Ok(TPKECipherText {
            U: U, V: V, W: W
        })
    }

    fn verify_ciphertext(&self, c: TPKECipherText) -> bool {
        unimplemented!();
    }

    fn verify_share(&self, i: Fr, Ui: u64, c: TPKECipherText) -> bool {
        unimplemented!();
    }

    fn combine_shares(&self, c: TPKECipherText, shares: &[Fr]) -> Vec<u8> {
        unimplemented!();
    }
}
impl TPKEPrivateKey {
    fn new(pk: TPKEPublicKey, sk: Fr) -> Self {
        Self {
            pk: pk,
            sk: sk
        }
    }

    fn decrypt_share(&self, c: TPKECipherText) -> G1 {
        return  c.U.mul(&self.sk.into_repr());
    }
}

fn hashH(g: G1, x: &[u8]) -> G2 {
    let mut serialized = Vec::new();
    g.serialize(&mut serialized);
    serialized.extend_from_slice(x);
    G2::from(
        G2Affine::from_random_bytes(&serialized).unwrap()
        )
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
