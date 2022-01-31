use std::{fmt, ops::{Mul, Add, Sub, Div}, cmp::Ordering};
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{Field, PrimeField, Zero, One};
use ark_bls12_381::{G1Projective as G, G1Affine as GAffine, Fr};
use std::collections::hash_set::HashSet;

pub struct TPKEPublicKey {
    l: u64,
    k: u64,
    VK: G,
    VKs: Vec<G>,
}

pub struct TPKEPrivateKey {
    pk: TPKEPublicKey,
    sk: Fr,
}

pub struct TPKECipherText {
    U: G,
    V: Vec<u8>,
    W: G
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
    fn new(l: u64, k: u64, VK: G, VKs: &[G]) -> Self {
        Self {
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
        unimplemented!();
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

    fn decrypt_share(&self, c: TPKECipherText) -> G {
        return  c.U.mul(&self.sk.into_repr());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
