use crate::HashError;
use ark_ec::ProjectiveCurve;

mod try_and_increment;
pub use try_and_increment::TryAndIncrement;

mod poseidon_for_bls12_377;
pub use poseidon_for_bls12_377::PoseidonTryAndIncrement;

/// Trait for hashing arbitrary data to a group element on an elliptic curve.
pub trait HashToCurve<Output: ProjectiveCurve> {
    /// Given a domain separator, a message and potentially some extra data, produces
    /// a hash of them which is a curve point.
    fn hash(domain: &[u8], message: &[u8], extra_data: &[u8]) -> Result<Output, HashError>;
}

/// Given `n` bytes, it returns the value rounded to the nearest multiple of 256 bits (in bytes)
/// e.g. 1. given 48 = 384 bits, it will return 64 bytes (= 512 bits)
///      2. given 96 = 768 bits, it will return 96 bytes (no rounding needed since 768 is already a
///         multiple of 256)
pub fn hash_length(n: usize) -> usize {
    let bits = (n * 8) as f64 / 256.0;
    let rounded_bits = bits.ceil() * 256.0;
    rounded_bits as usize / 8
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hash_length() {
        assert_eq!(hash_length(48), 64);
        assert_eq!(hash_length(96), 96);
    }
}
