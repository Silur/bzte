# bzte
<p style="text-align: center;">
<a href="https://deps.rs/repo/github/silur/bzte"><img src="https://deps.rs/repo/github/silur/bzte/status.svg"></
a>
<a href="https://docs.rs/bzte"><img src="https://img.shields.io/docsrs/bzte"></a>
</p>

## A rust implementation of the <a href="https://cpb-us-w2.wpmucdn.com/sites.uab.edu/dist/a/68/files/2020/01/globecom03-p1491.pdf">Baek-Zheng threshold cryptosystem</a> on top of BLS12-381 using arkworks

## Why threshold encrypt?

The advantage of threshold encryption over splitting a single symmetric encryption key using SSS is that
at the end of SSS, a single vulnerable secret key emerges that all parties could observe at the end of the proto
col. However with a TPKE scheme, combining the shares do not result in any sensitive information besides the dec
rypted plaintext at the end. This makes reusing the same key shares for multiple messages safely, using only one
 trusted setup (or a trustless DKG).

## Usage

```rust
use bzte::{keygen};

let (pk, sks) = keygen(10, 5);
let m = sha256(b"thats my kung fu"); // only supports messages up to 256 bits!
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
```

To serialiaize/deserialize keys or the ciphertext, use the provided `.to_bytes()`/`.from_bytes()` methods respec
tively.

## Disclaimer

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See http://www.wassenaar.org/ for more information.
