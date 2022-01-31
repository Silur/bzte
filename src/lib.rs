use std::{fmt, ops::Mul};
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{Field, PrimeField};
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
}
impl std::error::Error for TPKEError {}
impl fmt::Display for TPKEError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TPKEError::InvalidLength => write!(f, "Invalid length"),
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

    fn lagrange(&self, indices: Vec<u32>, j: u32) -> Result<Fr, TPKEError> {
        unimplemented!();
    }

    fn encrypt(&self, m: &[u8]) -> TPKECipherText {
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
