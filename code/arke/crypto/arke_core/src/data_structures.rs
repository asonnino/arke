use ark_bls12_377::Bls12_377;
use ark_crypto_primitives::SNARK;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use hash_functions::{poseidon377_parameters, HashError, PoseidonTryAndIncrement};
use proof_essentials::zkp::proofs::schnorr_identification::proof::Proof as DLOGProof;
use secret_sharing::shamir_secret_sharing::SecretShare;
use serde::de::Error;

/* --------------------------------------------------------------------------------------
ID-NIKE data structures
-------------------------------------------------------------------------------------- */

/// Arke public parameters
#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BLSPublicParameters<E: PairingEngine> {
    pub g1_gen: E::G1Projective,
    pub g2_gen: E::G2Projective,
}

impl<E: PairingEngine> BLSPublicParameters<E> {
    pub fn new() -> Self {
        Self {
            g1_gen: E::G1Projective::prime_subgroup_generator(),
            g2_gen: E::G2Projective::prime_subgroup_generator(),
        }
    }
}

pub type IssuancePublicParameters<E> = BLSPublicParameters<E>;

pub type RegistrationPublicParameters<E> = BLSPublicParameters<E>;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameters<ECompute: PairingEngine, EProve: PairingEngine> {
    pub threshold: usize,
    pub registration_params: RegistrationPublicParameters<ECompute>,
    pub issuance_params: IssuancePublicParameters<ECompute>,
    pub zk_params: BlindIDCircuitParameters<EProve>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Represents a human-readable identifier (phone number, twitter handle, etc)
pub struct UserID<'a>(pub &'a str);

impl<'a> UserID<'a> {
    pub fn new(id: &'a str) -> Self {
        Self(id)
    }

    pub fn hash_bls12_377_poseidon(
        &self,
        extra_data: &[u8],
    ) -> Result<HashedID<Bls12_377>, HashError> {
        let params = poseidon377_parameters();

        // hash to G1
        let sponge_for_g1 = PoseidonSponge::new(&params);
        let mut try_and_increment_g1 = PoseidonTryAndIncrement::new(sponge_for_g1);
        let (g1_hash, g1_attempts) =
            try_and_increment_g1.hash_to_bls12_377_g1(self.0.as_bytes(), extra_data)?;
        let combined_g1 = HashWithAttempts {
            hash: g1_hash,
            attempts: g1_attempts,
        };

        // hash to G2
        let sponge_for_g2 = PoseidonSponge::new(&params);
        let mut try_and_increment_g2 = PoseidonTryAndIncrement::new(sponge_for_g2);
        let (g2_hash, g2_attempts) =
            try_and_increment_g2.hash_to_bls12_377_g2(self.0.as_bytes(), extra_data)?;
        let combined_g2 = HashWithAttempts {
            hash: g2_hash,
            attempts: g2_attempts,
        };

        let hashed_id_bundle = HashedID {
            g1: combined_g1,
            g2: combined_g2,
        };
        Ok(hashed_id_bundle)
    }
}

/// An EC point obtained from hashing and the corresponding number of attempts
pub struct HashWithAttempts<P: ProjectiveCurve> {
    pub hash: P,
    pub attempts: usize,
}

/// A container structure for a hashed UserID
pub struct HashedID<E: PairingEngine> {
    pub g1: HashWithAttempts<E::G1Projective>,
    pub g2: HashWithAttempts<E::G2Projective>,
}

/// Issuer secret key is a Shamir secret share
pub type IssuerSecretKey<E> = SecretShare<<E as PairingEngine>::Fr>;

/// An issuer public key is composed of each generator taken to the power of the secret key share
#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuerPublicKey<E: PairingEngine> {
    pub left: E::G2Projective,
    pub right: E::G1Projective,
    pub index: usize,
}

impl<E: PairingEngine> IssuerPublicKey<E> {
    pub fn new(pp: &IssuancePublicParameters<E>, sk: &IssuerSecretKey<E>) -> Self {
        let left_pk = pp.g2_gen.mul(sk.value.into_repr());

        let right_pk = pp.g1_gen.mul(sk.value.into_repr());

        Self {
            left: left_pk,
            right: right_pk,
            index: sk.index,
        }
    }
}

pub type RegistrarSecretKey<E> = <E as PairingEngine>::Fr;

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrarPublicKey<E: PairingEngine> {
    pub left: E::G2Projective,
    pub right: E::G1Projective,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationAttestation<E: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
}

impl<E: PairingEngine> RegistrationAttestation<E> {
    pub fn blind(&self, blinding_factor: &E::Fr) -> BlindRegistrationAttestation<E> {
        BlindRegistrationAttestation {
            left: self.left.mul(blinding_factor.into_repr()),
            right: self.right.mul(blinding_factor.into_repr()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindRegistrationAttestation<E: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindID<E: PairingEngine, EProof: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
    pub proof: <Groth16<EProof> as SNARK<EProof::Fr>>::Proof,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindPartialSecretKey<E: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
    pub index: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PartialSecretKey<E: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
    pub index: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserSecretKey<E: PairingEngine> {
    pub left: E::G1Projective,
    pub right: E::G2Projective,
}

pub type SharedSeed<E> = <E as PairingEngine>::Fqk;

/* --------------------------------------------------------------------------------------
Blind ID Circuit data structures
-------------------------------------------------------------------------------------- */

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlindIDCircuitParameters<E: PairingEngine> {
    pub num_of_domain_sep_bytes: usize,
    pub num_of_identifier_bytes: usize,
    pub num_of_blinding_factor_bits: usize,
    pub proving_key: ProvingKey<E>,
    pub verifying_key: VerifyingKey<E>,
}

/* --------------------------------------------------------------------------------------
Unlinkable Handshake data structures
-------------------------------------------------------------------------------------- */

pub type SymmetricKey = Vec<u8>;

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct StoreKey {
    pub point: ark_bw6_761::G1Projective,
    buf: Vec<u8>,
}

impl From<ark_bw6_761::G1Projective> for StoreKey {
    fn from(point: ark_bw6_761::G1Projective) -> Self {
        let mut buf = Vec::new();
        point
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize G1Projective");
        Self { point, buf }
    }
}

impl std::hash::Hash for StoreKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.point.hash(state)
    }
}

impl serde::Serialize for StoreKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(&self.buf, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for StoreKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let point = ark_bw6_761::G1Projective::deserialize_unchecked(buf.as_slice())
            .map_err(D::Error::custom)?;
        Ok(Self { buf, point })
    }
}

impl std::fmt::Display for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "StoreKey({:?})", self.as_ref())
    }
}

impl AsRef<[u8]> for StoreKey {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for StoreKey {
    fn default() -> Self {
        let point = ark_bw6_761::G1Projective::default();
        let mut buf = Vec::new();
        point
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize G1Projective");
        Self { point, buf }
    }
}

pub type StoreValue = Vec<u8>;

pub type TagExponent = ark_bw6_761::Fr;

#[derive(Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct NIZKProof(pub DLOGProof<ark_bw6_761::G1Projective>);

impl serde::Serialize for NIZKProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::new();
        self.0
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize DLOGProof");
        serde_bytes::serialize(&buf, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for NIZKProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer).map_err(D::Error::custom)?;
        let proof = DLOGProof::<ark_bw6_761::G1Projective>::deserialize_unchecked(buf.as_slice())
            .map_err(D::Error::custom)?;
        Ok(Self(proof))
    }
}

#[cfg(test)]
mod test {
    use crate::StoreKey;

    #[test]
    fn serialize_store_key() {
        let key = StoreKey::default();
        let s = bincode::serialize(&key).unwrap();
        let d = bincode::deserialize(&s).unwrap();
        assert_eq!(key, d);
    }
}
