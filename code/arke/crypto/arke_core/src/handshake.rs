use std::marker::PhantomData;

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use ark_bls12_377::Bls12_377;
use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, PrimeField, ToBytes};
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::CanonicalSerialize;
use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge};
use blake2::Blake2s;
use hash_functions::{poseidon377_parameters, Blake2Xs, FixedLengthHash};
use proof_essentials::zkp::{
    proofs::schnorr_identification::SchnorrIdentification as DLOG, ArgumentOfKnowledge,
};
use rand::Rng;

use crate::{
    ARKEError, NIZKProof, SharedSeed, StoreKey, StoreValue, SymmetricKey, TagExponent, UserID,
};

/// Size of symmetric keys in bytes. Must match the block cipher chosen
pub const SIZE_SYMMETRIC_KEYS_IN_BYTES: usize = 32;

/// Domain separator for the key derivation function
pub const KEY_DERIVATION_FUNCTION_DOMAIN: &'static [u8] = b"DSforKDF";

/// Domain separator for extracting write and read tags
pub const TAG_DOMAIN: &'static [u8] = b"DSforTag";

pub const LOCATION_PROOF_RNG_SEED: &'static [u8] = b"Location Proof";

const NONCE_LENGTH_IN_BYTES: usize = 12;

/// Provides the functions required to implement the unlinkable handshake described in the paper. This type expects 4 generics:
/// - S: any type that is related to the shared seed
/// - KDF: type of key derivation function
/// - TDF: type of the tag derivation function
/// - Enc: type for our AEAD encryption+authentication scheme
pub struct UnlinkableHandshake<S, KDF, TDF, Enc: AeadInPlace>(PhantomData<(S, KDF, TDF, Enc)>);

type KDF = Blake2Xs;
type TDF = PoseidonSponge<ark_bls12_377::Fq>;

impl UnlinkableHandshake<Bls12_377, Blake2Xs, PoseidonSponge<ark_bls12_377::Fq>, Aes256Gcm> {
    /// Using a shared seed (derived from the ID-NIKE), we derive a symmetric key
    pub fn derive_symmetric_key(
        shared_seed: &SharedSeed<Bls12_377>,
    ) -> Result<SymmetricKey, ARKEError> {
        // Serialize the shared seed
        let mut serialized = Vec::new();
        shared_seed.serialize_uncompressed(&mut serialized)?;

        let symmetric_key = KDF::hash(
            KEY_DERIVATION_FUNCTION_DOMAIN,
            &serialized,
            SIZE_SYMMETRIC_KEYS_IN_BYTES,
        )?;

        Ok(symmetric_key)
    }

    pub fn derive_write_tag(
        shared_seed: &SharedSeed<Bls12_377>,
        my_id: &UserID,
        target_id: &UserID,
    ) -> Result<(StoreKey, TagExponent), ARKEError> {
        if my_id == target_id {
            return Err(ARKEError::IdenticalIDs);
        };

        let poseidon377_parameters = poseidon377_parameters();
        let mut sponge = TDF::new(&poseidon377_parameters);

        let exponent = match my_id < target_id {
            true => Self::append_zero_and_derive_exponent(&mut sponge, shared_seed),
            false => Self::append_one_and_derive_exponent(&mut sponge, shared_seed),
        };

        let generator = ark_bw6_761::G1Projective::prime_subgroup_generator();

        let write_tag = generator.mul(exponent.into_repr());

        Ok((write_tag.into(), exponent))
    }

    pub fn derive_read_tag(
        shared_seed: &SharedSeed<Bls12_377>,
        my_id: &UserID,
        target_id: &UserID,
    ) -> Result<StoreKey, ARKEError> {
        if my_id == target_id {
            return Err(ARKEError::IdenticalIDs);
        };

        let poseidon377_parameters = poseidon377_parameters();
        let mut sponge = TDF::new(&poseidon377_parameters);

        let exponent = match my_id < target_id {
            true => Self::append_one_and_derive_exponent(&mut sponge, shared_seed),
            false => Self::append_zero_and_derive_exponent(&mut sponge, shared_seed),
        };

        let generator = ark_bw6_761::G1Projective::prime_subgroup_generator();

        let read_tag = generator.mul(exponent.into_repr());

        Ok(read_tag.into())
    }

    pub fn prove_write_location<B: ToBytes, R: Rng>(
        write_tag: &StoreKey,
        exponent: &TagExponent,
        session_info: &B,
        rng: &mut R,
    ) -> Result<NIZKProof, ARKEError> {
        let generator = ark_bw6_761::G1Projective::prime_subgroup_generator();

        let seed = to_bytes![LOCATION_PROOF_RNG_SEED, session_info]?;
        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&seed);

        let proof = DLOG::prove(
            rng,
            &generator.into_affine(),
            &write_tag.point.into_affine(),
            exponent,
            &mut fs_rng,
        )?;

        Ok(NIZKProof { 0: proof })
    }

    pub fn verify_write_location<B: ToBytes>(
        write_tag: &StoreKey,
        proof: &NIZKProof,
        session_info: &B,
    ) -> Result<(), ARKEError> {
        let generator = ark_bw6_761::G1Projective::prime_subgroup_generator();

        let seed = to_bytes![LOCATION_PROOF_RNG_SEED, session_info]?;
        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&seed);

        DLOG::verify(
            &generator.into_affine(),
            &write_tag.point.into_affine(),
            &proof.0,
            &mut fs_rng,
        )?;

        Ok(())
    }

    pub fn encrypt_message<R: Rng>(
        symmetric_key: &SymmetricKey,
        write_location: &StoreKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, StoreValue), ARKEError> {
        let mut iv_bytes = [0u8; NONCE_LENGTH_IN_BYTES];
        rng.fill(&mut iv_bytes);

        let mut associated_data = Vec::new();
        write_location.serialize(&mut associated_data)?;

        let cipher = Aes256Gcm::new_from_slice(symmetric_key)?;

        let mut buffer = message.to_vec();
        let iv = Nonce::from_slice(&iv_bytes);

        cipher.encrypt_in_place(&iv, &associated_data, &mut buffer)?;

        Ok((iv_bytes.to_vec(), buffer))
    }

    pub fn decrypt_message(
        symmetric_key: &SymmetricKey,
        write_location: &StoreKey,
        iv_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ARKEError> {
        let mut associated_data = Vec::new();
        write_location.serialize(&mut associated_data)?;

        let cipher = Aes256Gcm::new_from_slice(symmetric_key)?;

        let iv = Nonce::from_slice(&iv_bytes);
        let mut buffer = ciphertext.to_vec();

        cipher.decrypt_in_place(iv, &associated_data, &mut buffer)?;

        Ok(buffer)
    }

    fn append_one_and_derive_exponent(
        sponge: &mut PoseidonSponge<ark_bw6_761::Fr>,
        shared_seed: &SharedSeed<Bls12_377>,
    ) -> ark_bw6_761::Fr {
        let one: &[u8] = b"1";
        sponge.absorb(&TAG_DOMAIN);
        sponge.absorb(&to_bytes![shared_seed].unwrap());
        sponge.absorb(&one);

        sponge.squeeze_native_field_elements(1)[0]
    }

    fn append_zero_and_derive_exponent(
        sponge: &mut PoseidonSponge<ark_bw6_761::Fr>,
        shared_seed: &SharedSeed<Bls12_377>,
    ) -> ark_bw6_761::Fr {
        let zero: &[u8] = b"0";
        sponge.absorb(&TAG_DOMAIN);
        sponge.absorb(&to_bytes![shared_seed].unwrap());
        sponge.absorb(&zero);

        sponge.squeeze_native_field_elements(1)[0]
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use crate::{random_id, UnlinkableHandshake, UserID, SIZE_SYMMETRIC_KEYS_IN_BYTES};

    #[test]
    fn test_symmetric_key() {
        let rng = &mut thread_rng();

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        let symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        assert_eq!(SIZE_SYMMETRIC_KEYS_IN_BYTES, symmetric_key.len());
        println!("{:?}", symmetric_key)
    }

    #[test]
    fn test_tags_match() {
        let rng = &mut thread_rng();

        let identifier_length = 8;

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let _symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        let (alice_write_tag, _alice_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &alice_id, &bob_id).unwrap();
        let (bob_write_tag, _bob_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &bob_id, &alice_id).unwrap();

        let alice_read_tag =
            UnlinkableHandshake::derive_read_tag(&shared_seed, &alice_id, &bob_id).unwrap();
        let bob_read_tag =
            UnlinkableHandshake::derive_read_tag(&shared_seed, &bob_id, &alice_id).unwrap();

        assert_eq!(alice_write_tag, bob_read_tag);
        assert_eq!(alice_read_tag, bob_write_tag);
    }

    #[test]
    fn test_accept_valid_proof() {
        let rng = &mut thread_rng();

        let identifier_length = 8;

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let _symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        let (alice_write_tag, alice_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &alice_id, &bob_id).unwrap();

        let mut session_id = [0u8; 4];
        rng.fill(&mut session_id);

        let proof = UnlinkableHandshake::prove_write_location(
            &alice_write_tag,
            &alice_exponent,
            &session_id,
            rng,
        )
        .unwrap();

        UnlinkableHandshake::verify_write_location(&alice_write_tag, &proof, &session_id).unwrap();
    }

    #[test]
    fn test_reject_invalid_proof() {
        let rng = &mut thread_rng();

        let identifier_length = 8;

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let _symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        let (alice_write_tag, alice_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &alice_id, &bob_id).unwrap();

        let mut session_id = [0u8; 4];
        rng.fill(&mut session_id);

        let proof = UnlinkableHandshake::prove_write_location(
            &alice_write_tag,
            &alice_exponent,
            &session_id,
            rng,
        )
        .unwrap();

        let another_write_tag = ark_bw6_761::G1Projective::rand(rng);

        assert!(UnlinkableHandshake::verify_write_location(
            &another_write_tag.into(),
            &proof,
            &session_id
        )
        .is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let rng = &mut thread_rng();

        let identifier_length = 8;
        let message = b"this is a message";

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        let (alice_write_tag, _alice_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &alice_id, &bob_id).unwrap();

        let (iv, ciphertext) =
            UnlinkableHandshake::encrypt_message(&symmetric_key, &alice_write_tag, message, rng)
                .unwrap();

        let recovered_message = UnlinkableHandshake::decrypt_message(
            &symmetric_key,
            &alice_write_tag,
            &iv,
            &ciphertext,
        )
        .unwrap();

        assert_eq!(message.to_vec(), recovered_message);
    }

    #[test]
    fn test_reject_wrong_associated_data() {
        let rng = &mut thread_rng();

        let identifier_length = 8;
        let message = b"this is a message";

        let shared_seed = ark_bls12_377::Fq12::rand(rng);

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let symmetric_key = UnlinkableHandshake::derive_symmetric_key(&shared_seed).unwrap();

        let (alice_write_tag, _alice_exponent) =
            UnlinkableHandshake::derive_write_tag(&shared_seed, &alice_id, &bob_id).unwrap();

        let (iv, ciphertext) =
            UnlinkableHandshake::encrypt_message(&symmetric_key, &alice_write_tag, message, rng)
                .unwrap();

        let another_location = ark_bw6_761::G1Projective::rand(rng);

        let attempted_recovered_message = UnlinkableHandshake::decrypt_message(
            &symmetric_key,
            &another_location.into(),
            &iv,
            &ciphertext,
        );

        assert!(attempted_recovered_message.is_err())
    }
}
