use std::{fmt, ops::{Mul, Add, Sub, Div}, cmp::Ordering, collections::HashMap};
use ark_std::UniformRand;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{Field, PrimeField, Zero, One, FromBytes};
use ark_ec::PairingEngine;
use ark_bls12_381::{
    G1Projective as G1, 
    G1Affine, G2Affine, 
    G2Projective as G2, 
    Fr,
    Bls12_381};
use std::collections::hash_set::HashSet;
use sha2::Digest;

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    let ret = hasher.finalize().to_vec();
    ret
}

fn hash_to_G1(b: &[u8]) -> G1 {
    let mut nonce = 0u32;
    loop {
        let c = [b"bzte-domain-g1", b, b"bzte-sep", &nonce.to_be_bytes()].concat();
        match G1Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => return v.mul_by_cofactor_to_projective(),
            None => nonce += 1
        }
    }
}

fn hash_to_G2(b: &[u8]) -> G2 {
    let mut rng = rand::thread_rng();
    let mut nonce = 0u32;
    loop {
        let c = [b"bzte-domain-g2", b, b"bzte-sep", &nonce.to_be_bytes()].concat();
        match G2Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => return v.mul_by_cofactor_to_projective(),
            None => nonce += 1
        }
    }
}

#[derive(Debug, Clone)]
pub struct TPKEPublicKey {
    l: u64,
    k: u64,
    g1: G1,
    g2: G2,
    VK: G2,
    VKs: Vec<G2>,
}

#[derive(Debug)]
pub struct TPKEPrivateKey {
    pk: TPKEPublicKey,
    sk: Fr,
}

#[derive(Debug, Clone)]
pub struct TPKECipherText {
    U: G1,
    V: Vec<u8>,
    W: G2
}

#[derive(Debug)]
pub enum TPKEError {
    InvalidLength,
    InvalidValue,
    InvalidCiphertext,
    InvalidShare
}
impl std::error::Error for TPKEError {}
impl fmt::Display for TPKEError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TPKEError::InvalidLength => write!(f, "Invalid length"),
            TPKEError::InvalidValue => write!(f, "Invalid value"),
            TPKEError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            TPKEError::InvalidShare => write!(f, "Invalid share"),
        }
    }
}

impl TPKEPublicKey {
    pub fn new(l: u64, k: u64, VK: G2, VKs: &[G2]) -> Self {
        let g1 = hash_to_G1(b"generator");
        let g2 = hash_to_G2(b"generator");

        Self {
            g1: g1,
            g2: g2,
            l: l,
            k: k,
            VK: VK,
            VKs: VKs.to_vec()
        }
    }

    fn lagrange(&self, indices: &[u64], j: u64) -> Result<Fr, TPKEError> {
        if indices.len() != self.k as usize {
            return Err(TPKEError::InvalidLength);
        }
        let mut sorted = indices.to_vec();
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
                Ordering::Equal => Fr::one(),
                _ => Fr::one().sub(Fr::from(*x as u128)).sub(Fr::one())
            }
        }).fold(Fr::one(), |acc, x| {
            acc.mul(x)
        });

        let den = sorted.iter().map(|x| { 
            match x.cmp(&j) {
                Ordering::Equal => Fr::one(),
                _ => Fr::from(j).sub(Fr::from(*x as u128))
            }
        }).fold(Fr::one(), |acc, x| {
            acc.mul(x)
        });

        Ok(num.div(den))
    }

    pub fn encrypt(&self, m: &[u8]) -> Result<TPKECipherText, TPKEError> {
        if m.len() != 32 { return Err(TPKEError::InvalidLength); }
        let mut rng = rand::thread_rng();
        let r = Fr::rand(&mut rng).into_repr();
        let U = self.g1.mul(r);
        let VKr = self.VK.mul(r);
        let mut V = Vec::new();
        VKr.serialize(&mut V).unwrap();
        V = sha256(&V);
        for i in 0..32 {
            V[i] ^= m[i];
        }
        let h = hashH(U, &V);
        let W = h.mul(r);
        let p1 = Bls12_381::pairing(self.g1, W);
        let p2 = Bls12_381::pairing(U, h);
        Ok(TPKECipherText {
            U: U, V: V, W: W
        })
    }

    fn verify_ciphertext(&self, c: &TPKECipherText) -> bool {
        let h = hashH(c.U, &c.V);
        let p1 = Bls12_381::pairing(self.g1, c.W);
        let p2 = Bls12_381::pairing(c.U, h);
        p1 == p2
    }

    fn verify_share(&self, i: usize, Ui: G1, c: &TPKECipherText) -> bool {
        if i < 0usize || i > self.l.try_into().unwrap() { return false; }
        let yi = self.VKs[i];
        let p1 = Bls12_381::pairing(Ui, self.g2);
        let p2 = Bls12_381::pairing(c.U, yi);
        println!("{}", p1 == p2);
        p1 == p2
    }

    fn combine_shares(&self, c: &TPKECipherText, shares: HashMap<usize, G1>) -> Result<Vec<u8>, TPKEError> {
        if !self.verify_ciphertext(c) {
            return Err(TPKEError::InvalidCiphertext);
        }
        let mut r = hash_to_G1(b"bzte-id");
        let indices: Vec<u64> = shares.keys().map(|i| (*i).try_into().unwrap()).collect();
        for (j, share) in shares.iter() {
            if !self.verify_share(*j, *share, c) {
                return Err(TPKEError::InvalidShare);
            }
        }
        r = shares.iter().map(|(k, v)| {
            v.mul(self.lagrange(&indices, (*k).try_into().unwrap()).unwrap().into_repr())
        }).fold(r, |acc, x| {
            acc.add(x)
        });
        let mut ret = Vec::new();
        r.serialize(&mut ret);
        for i in 0..ret.len() {
            ret[i] ^= c.V[i];
        }
        Ok(ret)
    }
}

impl TPKEPrivateKey {
    fn new(pk: TPKEPublicKey, sk: Fr) -> Self {
        Self {
            pk: pk,
            sk: sk
        }
    }

    fn decrypt_share(&self, c: &TPKECipherText) -> Result<G1, TPKEError> {
        match self.pk.verify_ciphertext(c) {
            true => Ok(c.U.mul(&self.sk.into_repr())),
            false => Err(TPKEError::InvalidCiphertext)
        }
    }
}

fn hashH(g: G1, x: &[u8]) -> G2 {
    let mut serialized = Vec::new();
    g.serialize(&mut serialized);
    serialized.extend_from_slice(x);
    hash_to_G2(&serialized)
}

pub fn keygen(l: u64, k: u64) -> (TPKEPublicKey, Vec<TPKEPrivateKey>) {
    let mut rng = rand::thread_rng();
    let a = vec![Fr::rand(&mut rng); k.try_into().unwrap()];
    let sk = a[0];
    let eval = | x: u64 | {
        let mut y = Fr::zero();
        let mut xx = Fr::one();
        for coeff in a.clone() { // FIXME
            y = y.add(Fr::from(xx).mul(Fr::from(coeff)));
            xx = xx.mul(Fr::from(x));
        }
        return y;
    };
    let SKs: Vec<Fr> = (1..k+1).map(eval).collect();
    assert_eq!(eval(0), sk);

    let g2 = hash_to_G2(b"bzte-g2");
    let VK = g2.mul(sk.into_repr());
    let VKs: Vec<G2> = SKs.iter().map(|x| { g2.mul(x.into_repr()) }).collect();

    let tpk = TPKEPublicKey::new(l, k, VK, &VKs);
    let tsks = SKs.iter().map(|x| { TPKEPrivateKey::new(tpk.clone(), x.clone()) }).collect();
    (tpk, tsks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let (pk, sks) = keygen(10, 5);
        let m = sha256(b"thats my kung fu");
        let C = pk.encrypt(&m).unwrap();
        assert!(pk.verify_ciphertext(&C));
        let shares = sks.iter().map(|sk| { sk.decrypt_share(&C).unwrap() });
        for (i, share) in shares.enumerate() {
            assert!(pk.verify_share(i, share, &C));
        }
    }
}
