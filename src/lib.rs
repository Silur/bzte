use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::PairingEngine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::UniformRand;
use sha2::Digest;
use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt,
    ops::{Add, Div, Mul, Sub},
};

fn sha256(b: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b);
    hasher.finalize().to_vec()
}

fn hash_to_g1(b: &[u8]) -> G1 {
    let mut nonce = 0u32;
    loop {
        let c = [b"bzte-domain-g1", b, b"bzte-sep", &nonce.to_be_bytes()].concat();
        match G1Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_projective();
            }
            None => nonce += 1,
        }
    }
}

fn hash_to_g2(b: &[u8]) -> G2 {
    let mut nonce = 0u32;
    loop {
        let c = [b"bzte-domain-g2", b, b"bzte-sep", &nonce.to_be_bytes()].concat();
        match G2Affine::from_random_bytes(&sha256(&c)) {
            Some(v) => {
                // if v.is_in_correct_subgroup_assuming_on_curve() { return v.into(); }
                return v.mul_by_cofactor_to_projective();
            }
            None => nonce += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Holds the public key and generators for the TPKE scheme
pub struct TPKEPublicKey {
    l: u64,
    k: u64,
    g1: G1,
    g2: G2,
    vk: G2,
    vks: Vec<G2>,
}

#[derive(Debug, PartialEq)]
/// Holds the secret scalar and a copy of the public key of the TPKE scheme
pub struct TPKEPrivateKey {
    pk: TPKEPublicKey,
    sk: Fr,
    index: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TPKECipherText {
    u: G1,
    v: Vec<u8>,
    w: G2,
}

#[derive(Debug)]
pub enum TPKEError {
    InvalidLength,
    InvalidValue,
    InvalidCiphertext,
    InvalidShare,
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
    /// creates a k-of-l threshold setup, where l keys are required out of
    /// l to decrypt a message
    pub fn new(l: u64, k: u64, vk: G2, vks: &[G2]) -> Self {
        let g1 = hash_to_g1(b"generator");
        let g2 = hash_to_g2(b"generator");

        Self {
            g1: g1,
            g2: g2,
            l: l,
            k: k,
            vk: vk,
            vks: vks.to_vec(),
        }
    }

    fn lagrange(&self, indices: &[u64], j: u64) -> Result<Fr, TPKEError> {
        if indices.len() != self.k as usize {
            return Err(TPKEError::InvalidLength);
        }
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != indices.len() {
            return Err(TPKEError::InvalidValue);
        }
        let mut contains_j = false;
        for i in indices.iter() {
            if *i == j {
                contains_j = true;
                break;
            }
            if i > &self.l {
                return Err(TPKEError::InvalidValue);
            }
        }
        if !contains_j {
            return Err(TPKEError::InvalidValue);
        }
        let num = sorted
            .iter()
            .map(|x| match x.cmp(&j) {
                Ordering::Equal => Fr::one(),
                _ => Fr::zero().sub(Fr::from(*x as u128)).sub(Fr::one()),
            })
            .fold(Fr::one(), |acc, x| acc.mul(x));

        let den = sorted
            .iter()
            .map(|x| match x.cmp(&j) {
                Ordering::Equal => Fr::one(),
                _ => Fr::from(j).sub(Fr::from(*x as u128)),
            })
            .fold(Fr::one(), |acc, x| acc.mul(x));

        Ok(num.div(den))
    }

    /// encrypts the message to a given public key
    pub fn encrypt(&self, m: &[u8]) -> Result<TPKECipherText, TPKEError> {
        if m.len() != 32 {
            return Err(TPKEError::InvalidLength);
        }
        let mut rng = rand::thread_rng();
        let r = Fr::rand(&mut rng).into_repr();
        let u = self.g1.mul(r);
        let vkr = Bls12_381::pairing(self.g1, self.vk.mul(r));
        let mut v = Vec::new();
        vkr.serialize(&mut v).unwrap();
        v = sha256(&v);
        for i in 0..32 {
            v[i] ^= m[i];
        }
        let h = hash_h(u, &v);
        let w = h.mul(r);
        // let p1 = Bls12_381::pairing(self.g1, w);
        // let p2 = Bls12_381::pairing(u, h);
        // assert_eq!(p1, p2);
        Ok(TPKECipherText { u: u, v: v, w: w })
    }

    /// verify that the pairings inside the ciphertexts add up
    pub fn verify_ciphertext(&self, c: &TPKECipherText) -> bool {
        let h = hash_h(c.u, &c.v);
        let p1 = Bls12_381::pairing(self.g1, c.w);
        let p2 = Bls12_381::pairing(c.u, h);
        p1 == p2
    }

    /// verify that the shares given as parameter are valid
    pub fn verify_share(&self, i: usize, ui: G1, c: &TPKECipherText) -> bool {
        if i > self.l.try_into().unwrap() {
            return false;
        }
        let yi = self.vks[i];
        let p1 = Bls12_381::pairing(ui, self.g2);
        let p2 = Bls12_381::pairing(c.u, yi);
        p1 == p2
    }

    /// decrypts a message using the provided key shares
    pub fn combine_shares(
        &self,
        c: &TPKECipherText,
        shares: &HashMap<usize, G1>,
    ) -> Result<Vec<u8>, TPKEError> {
        if !self.verify_ciphertext(c) {
            return Err(TPKEError::InvalidCiphertext);
        }
        let indices: Vec<u64> = shares.keys().map(|i| (*i).try_into().unwrap()).collect();
        for (j, share) in shares.iter() {
            if !self.verify_share(*j, *share, c) {
                return Err(TPKEError::InvalidShare);
            }
        }
        let r = Bls12_381::pairing(
            shares
                .iter()
                .map(|(k, v)| {
                    v.mul(
                        self.lagrange(&indices, (*k).try_into().unwrap())
                            .unwrap()
                            .into_repr(),
                    )
                })
                .fold(G1::zero(), |acc, x| acc.add(x)),
            self.g2,
        );
        let mut ret = Vec::new();
        r.serialize(&mut ret).unwrap();
        ret = sha256(&ret);
        for (i, ri) in ret.iter_mut().enumerate().take(32) {
            *ri ^= c.v[i];
        }
        Ok(ret)
    }

    /// serializes the public key
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut r = Vec::new();
        r.extend_from_slice(&self.l.to_be_bytes());
        r.extend_from_slice(&self.k.to_be_bytes());
        let mut b = Vec::new();
        self.g1.serialize(&mut b)?;
        r.append(&mut b);
        self.g2.serialize(&mut b)?;
        r.append(&mut b);
        self.vk.serialize(&mut b)?;
        r.append(&mut b);
        for vk in self.vks.iter() {
            vk.serialize(&mut b)?;
            r.append(&mut b);
        }
        Ok(r)
    }

    /// create a public key from a byte slice
    pub fn from_bytes(b: &[u8]) -> Result<Self, SerializationError> {
        let mut i = 0usize;
        let l = u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        i += 8;
        let k = u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        i += 8;
        let g1: G1 = G1::deserialize(&b[i..i + 48])?;
        i += 48;
        let g2: G2 = G2::deserialize(&b[i..i + 96])?;
        i += 96;
        let vk: G2 = G2::deserialize(&b[i..i + 96])?;
        i += 96;
        let mut vks: Vec<G2> = Vec::new();
        for _ in 0..l {
            vks.push(G2::deserialize(&b[i..i + 96])?);
            i += 96;
        }
        Ok(Self {
            l,
            k,
            g1,
            g2,
            vk,
            vks,
        })
    }
}

impl TPKEPrivateKey {
    /// create a new secret key for `pk`, with index `i`
    pub fn new(pk: TPKEPublicKey, sk: Fr, i: u64) -> Self {
        Self {
            pk: pk,
            sk: sk,
            index: i,
        }
    }

    /// recover a ciphertext share locally
    pub fn decrypt_share(&self, c: &TPKECipherText) -> Result<G1, TPKEError> {
        match self.pk.verify_ciphertext(c) {
            true => Ok(c.u.mul(&self.sk.into_repr())),
            false => Err(TPKEError::InvalidCiphertext),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut r = self.pk.to_bytes()?;
        let mut b: Vec<u8> = Vec::new();
        self.sk.serialize(&mut b)?;
        r.append(&mut b);
        r.extend_from_slice(&self.index.to_be_bytes());
        Ok(r)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SerializationError> {
        let mut i = 0usize;
        let pk = TPKEPublicKey::from_bytes(&b[i..i + 1216])?;
        i += 1216;
        let sk = Fr::deserialize(&b[i..i + 32])?;
        i += 32;
        let i = u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        Ok(Self { pk, sk, index: i })
    }
}

impl TPKECipherText {
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut r: Vec<u8> = Vec::new();
        let mut b: Vec<u8> = Vec::new();
        self.u.serialize(&mut b)?;
        r.append(&mut b);
        self.w.serialize(&mut b)?;
        r.append(&mut b);
        b = self.v.clone();
        r.append(&mut b);
        Ok(r)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SerializationError> {
        let mut i = 0usize;
        let u = G1::deserialize(&b[i..i + 48]).unwrap();
        i += 48;
        let w = G2::deserialize(&b[i..i + 96]).unwrap();
        i += 96;
        let v: Vec<u8> = b[i..i + 32].to_vec();
        Ok(Self { u, v, w })
    }
}

fn hash_h(g: G1, x: &[u8]) -> G2 {
    let mut serialized = Vec::new();
    g.serialize(&mut serialized).unwrap();
    serialized.extend_from_slice(x);
    hash_to_g2(&serialized)
}

/// Creates a new k-of-l scheme, then returns the verifier public key
/// and the correspondng shares
pub fn keygen(l: u64, k: u64) -> (TPKEPublicKey, Vec<TPKEPrivateKey>) {
    let mut rng = rand::thread_rng();
    let a = vec![Fr::rand(&mut rng); k.try_into().unwrap()];
    let sk = a[0];
    let eval = |x: u64| {
        let mut y = Fr::zero();
        let mut xx = Fr::one();
        for coeff in a.clone() {
            y = y.add(xx.mul(coeff));
            xx = xx.mul(Fr::from(x));
        }
        y
    };
    let sks: Vec<Fr> = (1..l + 1).map(eval).collect();

    let g2 = hash_to_g2(b"generator");
    let vk = g2.mul(sk.into_repr());
    let vks: Vec<G2> = sks.iter().map(|x| g2.mul(x.into_repr())).collect();

    let tpk = TPKEPublicKey::new(l, k, vk, &vks);
    let tsks = sks
        .iter()
        .enumerate()
        .map(|(i, x)| TPKEPrivateKey::new(tpk.clone(), *x, i.try_into().unwrap()))
        .collect();

    /* let indices: Vec<u64> = (0..k).collect();
    let rhs = (0..k)
        .map(|j| { tpk.lagrange(&indices, j).unwrap().mul(eval(j+1)) })
        .fold(Fr::zero(), |acc, x| { acc.add(x) });
    assert_eq!(eval(0), sk);
    assert_eq!(sk,rhs);
    */
    (tpk, tsks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let (pk, sks) = keygen(10, 5);
        let m = sha256(b"thats my kung fu");
        let c = pk.encrypt(&m).unwrap();
        assert!(pk.verify_ciphertext(&c));
        let shares: Vec<G1> = sks.iter().map(|sk| sk.decrypt_share(&c).unwrap()).collect();
        for (i, share) in shares.iter().enumerate() {
            assert!(pk.verify_share(i, *share, &c));
        }

        let mut partial_shares: HashMap<usize, G1> = HashMap::new();
        for i in 0..5 {
            partial_shares.insert(i, shares[i]);
        }
        let check = pk.combine_shares(&c, &partial_shares).unwrap();
        assert_eq!(check, m);

        partial_shares.insert(1, shares.get(1).unwrap().double());
        assert!(pk.combine_shares(&c, &partial_shares).is_err());

        let pk_serialized = pk.to_bytes().unwrap();
        let pk_deserialized = TPKEPublicKey::from_bytes(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        let sk_serialized = sks[0].to_bytes().unwrap();
        let sk_deserialized = TPKEPrivateKey::from_bytes(&sk_serialized).unwrap();
        assert_eq!(sks[0], sk_deserialized);

        let c_serialized = c.to_bytes().unwrap();
        let c_deserialized = TPKECipherText::from_bytes(&c_serialized).unwrap();
        assert_eq!(c, c_deserialized);
    }
}
