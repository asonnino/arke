use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_crypto_primitives::SNARK;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof};
use ark_std::{marker::PhantomData, One, UniformRand, Zero};
use hash_functions::bytes_le_to_bits_le;
use rand::{CryptoRng, Rng};
use secret_sharing::{
    shamir_secret_sharing::eval_lagrange_basis, SecretSharingScheme, ShamirSecretSharing,
};
use std::ops::AddAssign;

use crate::{
    ARKEError, BlindID, BlindIDCircuitParameters, BlindPartialSecretKey,
    BlindRegistrationAttestation, IssuancePublicParameters, IssuerPublicKey, IssuerSecretKey,
    PartialSecretKey, RegistrarPublicKey, RegistrarSecretKey, RegistrationAttestation,
    RegistrationPublicParameters, SharedSeed, UserID, UserSecretKey,
};

mod blind_id_proof;
pub use blind_id_proof::BlindIDCircuit;

/// The Arke ID-NIKE (identity-based non-interactive key exchange).
/// On top of the normal ID-NIKE properties, the Arke ID-NIKE allows to separate key-issuance
/// from user registration. Furthermore, the key-issuance authority is distributed
pub struct ThresholdObliviousIdNIKE<ECompute: PairingEngine, EProof: PairingEngine> {
    _pairing: PhantomData<ECompute>,
    _snark_curve: PhantomData<EProof>,
}

// This implementation block contains all the public ThresholdObliviousIdNIKE functions as
// described in the paper. Helper functions are defined in a following impl block
impl ThresholdObliviousIdNIKE<Bls12_377, BW6_761> {
    #[allow(non_snake_case)]
    /// Simulate the distributed key generation with $n$ parties of which $t$ are malicious.
    /// Returns public parameters and the honest parties' secret and public keys.
    pub fn simulate_issuers_DKG<R: Rng>(
        threshold: usize,
        number_of_participants: usize,
        rng: &mut R,
    ) -> Result<
        (
            IssuancePublicParameters<Bls12_377>,
            Vec<IssuerSecretKey<Bls12_377>>,
            Vec<IssuerPublicKey<Bls12_377>>,
        ),
        ARKEError,
    > {
        if threshold >= number_of_participants / 2 {
            return Err(ARKEError::TooManyAdversaries);
        }
        let number_of_honest_participants = number_of_participants - threshold;

        let pp_issuance = IssuancePublicParameters::new();
        let master_secret_key = ark_bls12_377::Fr::rand(rng);

        let issuers_secret_keys: Vec<IssuerSecretKey<Bls12_377>> =
            ShamirSecretSharing::generate_shares(
                &master_secret_key,
                number_of_participants,
                threshold,
                rng,
            )?
            .iter()
            .map(|&secret_key_share| secret_key_share.into())
            .collect();

        let honest_issuers_secret_keys =
            issuers_secret_keys[..number_of_honest_participants].to_vec();

        let honest_issuers_public_keys: Vec<IssuerPublicKey<Bls12_377>> =
            honest_issuers_secret_keys
                .iter()
                .map(|issuer_secret_key| IssuerPublicKey::new(&pp_issuance, &issuer_secret_key))
                .collect();

        Ok((
            pp_issuance,
            honest_issuers_secret_keys,
            honest_issuers_public_keys,
        ))
    }

    /// Setup algorithm for the registration authority
    pub fn setup_registration<R: Rng>(
        rng: &mut R,
    ) -> (
        RegistrationPublicParameters<Bls12_377>,
        RegistrarSecretKey<Bls12_377>,
        RegistrarPublicKey<Bls12_377>,
    ) {
        let pp_registration: RegistrationPublicParameters<Bls12_377> =
            RegistrationPublicParameters::new();
        let registrar_secret_key = ark_bls12_377::Fr::rand(rng);

        let registrar_public_key = RegistrarPublicKey::<Bls12_377> {
            left: pp_registration.g2_gen.mul(registrar_secret_key.into_repr()),
            right: pp_registration.g1_gen.mul(registrar_secret_key.into_repr()),
        };

        (pp_registration, registrar_secret_key, registrar_public_key)
    }

    /// Trusted setup for the proof of blinded identity
    pub fn setup_blind_id_proof<R: Rng + CryptoRng>(
        num_of_domain_sep_bytes: usize,
        num_of_identifier_bytes: usize,
        num_of_blinding_factor_bits: usize,
        rng: &mut R,
    ) -> Result<BlindIDCircuitParameters<BW6_761>, ARKEError> {
        let circuit: BlindIDCircuit<Bls12_377> = BlindIDCircuit::empty(
            num_of_domain_sep_bytes,
            num_of_identifier_bytes,
            num_of_blinding_factor_bits,
        );

        let (pk, vk) = Groth16::<BW6_761>::circuit_specific_setup(circuit.clone(), rng)?;

        let pp_zk = BlindIDCircuitParameters {
            num_of_domain_sep_bytes,
            num_of_identifier_bytes,
            num_of_blinding_factor_bits,
            proving_key: pk,
            verifying_key: vk,
        };

        Ok(pp_zk)
    }

    /// Register an identifier
    pub fn register(
        registrar_secret_key: &RegistrarSecretKey<Bls12_377>,
        user_id: &UserID,
        registrar_domain: &[u8],
    ) -> Result<RegistrationAttestation<Bls12_377>, ARKEError> {
        let hashed = user_id.hash_bls12_377_poseidon(registrar_domain)?;

        let left_token = hashed.g1.hash.mul(registrar_secret_key.into_repr());
        let right_token = hashed.g2.hash.mul(registrar_secret_key.into_repr());

        Ok(RegistrationAttestation {
            left: left_token,
            right: right_token,
        })
    }

    /// Blind an identifier and its corresponding registration attestation
    pub fn blind<R: Rng + CryptoRng>(
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        user_id: &UserID,
        registrar_domain: &[u8],
        registration_attestation: &RegistrationAttestation<Bls12_377>,
        rng: &mut R,
    ) -> Result<
        (
            ark_bls12_377::Fr,
            BlindID<Bls12_377, BW6_761>,
            BlindRegistrationAttestation<Bls12_377>,
        ),
        ARKEError,
    > {
        let blinding_factor = ark_bls12_377::Fr::rand(rng);
        let hashed = user_id.hash_bls12_377_poseidon(registrar_domain)?;

        let left_blinded = hashed.g1.hash.mul(blinding_factor.into_repr());
        let right_blinded = hashed.g2.hash.mul(blinding_factor.into_repr());
        let proof = Self::prove_blind_id(
            pp_zk,
            &left_blinded,
            hashed.g1.attempts,
            &right_blinded,
            hashed.g2.attempts,
            registrar_domain,
            user_id,
            &blinding_factor,
            rng,
        )?;

        let blind_id = BlindID {
            left: left_blinded,
            right: right_blinded,
            proof,
        };

        let blind_registration_attestation = registration_attestation.blind(&blinding_factor);

        Ok((blinding_factor, blind_id, blind_registration_attestation))
    }

    /// Check a blind token/id pair and return the corresponding blind partial secret key
    pub fn blind_partial_extract(
        pp_registration: &RegistrationPublicParameters<Bls12_377>,
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        registrar_public_key: &RegistrarPublicKey<Bls12_377>,
        issuer_partial_secret_key: &IssuerSecretKey<Bls12_377>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
        blind_registration_attestation: &BlindRegistrationAttestation<Bls12_377>,
        registrar_domain: &[u8],
    ) -> Result<BlindPartialSecretKey<Bls12_377>, ARKEError> {
        Self::verify_blind_extract_request(
            pp_registration,
            pp_zk,
            registrar_public_key,
            blind_id,
            blind_registration_attestation,
            registrar_domain,
        )?;
        // Self::verify_left_token(
        //     pp_registration,
        //     registrar_public_key,
        //     blind_id,
        //     blind_registration_attestation,
        // )?;
        // Self::verify_right_token(
        //     pp_registration,
        //     registrar_public_key,
        //     blind_id,
        //     blind_registration_attestation,
        // )?;
        // Self::verify_blind_id_proof(pp_zk, blind_id, registrar_domain)?;

        let blind_partial_user_key =
            Self::emit_blind_partial_key(issuer_partial_secret_key, blind_id);
        // let blind_partial_user_key = BlindPartialSecretKey {
        //     left: blind_id
        //         .left
        //         .mul(issuer_partial_secret_key.value.into_repr()),
        //     right: blind_id
        //         .right
        //         .mul(issuer_partial_secret_key.value.into_repr()),
        //     index: issuer_partial_secret_key.index,
        // };

        Ok(blind_partial_user_key)
    }

    /// Unblind a blind partial secret key
    pub fn unblind(
        blind_partial_user_key: &BlindPartialSecretKey<Bls12_377>,
        blinding_factor: &ark_bls12_377::Fr,
    ) -> PartialSecretKey<Bls12_377> {
        let inverse_blinding_factor = blinding_factor
            .inverse()
            .expect("BF is from prime field and should have an inverse");

        let partial_user_key = PartialSecretKey {
            left: blind_partial_user_key
                .left
                .mul(inverse_blinding_factor.into_repr()),
            right: blind_partial_user_key
                .right
                .mul(inverse_blinding_factor.into_repr()),
            index: blind_partial_user_key.index,
        };

        partial_user_key
    }

    pub fn verify_partial_secret_key(
        pp_issuance: &IssuancePublicParameters<Bls12_377>,
        user_id: &UserID,
        issuer_public_key: &IssuerPublicKey<Bls12_377>,
        registrar_domain: &[u8],
        partial_user_key: &PartialSecretKey<Bls12_377>,
    ) -> Result<(), ARKEError> {
        let hashed_id = user_id.hash_bls12_377_poseidon(registrar_domain)?;

        // Check left part of the partial user key
        if Bls12_377::pairing(partial_user_key.left, pp_issuance.g2_gen)
            != Bls12_377::pairing(hashed_id.g1.hash, issuer_public_key.left)
        {
            return Err(ARKEError::VerificationFailed);
        }

        // Check right part of the partial user key
        if Bls12_377::pairing(pp_issuance.g1_gen, partial_user_key.right)
            != Bls12_377::pairing(issuer_public_key.right, hashed_id.g2.hash)
        {
            return Err(ARKEError::VerificationFailed);
        }

        Ok(())
    }

    /// Combine $t+1$ partial secret keys to obtain a full secret key
    pub fn combine(
        partial_keys: &[PartialSecretKey<Bls12_377>],
        threshold: usize,
    ) -> Result<UserSecretKey<Bls12_377>, ARKEError> {
        if partial_keys.len() <= threshold {
            return Err(ARKEError::ThresholdNotMet);
        }

        let domain: Vec<ark_bls12_377::Fr> = partial_keys
            .iter()
            .map(|key_share| ark_bls12_377::Fr::from((key_share.index + 1) as u64))
            .collect(); // we add one because the secret shares are computed over [1..number_of_participants+1]

        let zero = ark_bls12_377::Fr::zero();
        let mut left_accumulator = ark_bls12_377::G1Projective::zero();
        let mut right_accumulator = ark_bls12_377::G2Projective::zero();

        for (i, share) in partial_keys[0..threshold].iter().enumerate() {
            let evaluated_lagrange_basis = eval_lagrange_basis(&domain, i, zero)?;
            left_accumulator.add_assign(share.left.mul(evaluated_lagrange_basis.into_repr()));
            right_accumulator.add_assign(share.right.mul(evaluated_lagrange_basis.into_repr()));
        }

        let user_secret_key = UserSecretKey {
            left: left_accumulator,
            right: right_accumulator,
        };

        Ok(user_secret_key)
    }

    /// Compute the shared key between two identifiers using a secret key and an identifier
    pub fn shared_key(
        user_secret_key: &UserSecretKey<Bls12_377>,
        user_id: &UserID,
        target_id: &UserID,
        registrar_domain: &[u8],
    ) -> Result<SharedSeed<Bls12_377>, ARKEError> {
        if user_id == target_id {
            return Err(ARKEError::IdenticalIDs);
        }

        let hashed_target = target_id.hash_bls12_377_poseidon(registrar_domain)?;

        let shared_seed = match user_id < target_id {
            true => Bls12_377::pairing(user_secret_key.left, hashed_target.g2.hash),
            false => Bls12_377::pairing(hashed_target.g1.hash, user_secret_key.right),
        };

        Ok(shared_seed)
    }
}

// Helper functions
impl ThresholdObliviousIdNIKE<Bls12_377, BW6_761> {
    fn prove_blind_id<R: Rng + CryptoRng>(
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        left_blinded: &ark_bls12_377::G1Projective,
        left_attempts: usize,
        right_blinded: &ark_bls12_377::G2Projective,
        right_attempts: usize,
        domain_separator_bytes: &[u8],
        user_id: &UserID,
        blinding_factor: &ark_bls12_377::Fr,
        rng: &mut R,
    ) -> Result<Proof<BW6_761>, ARKEError> {
        // Populate circuit
        let mut prover_assignment = BlindIDCircuit::empty(
            pp_zk.num_of_domain_sep_bytes,
            pp_zk.num_of_identifier_bytes,
            pp_zk.num_of_blinding_factor_bits,
        );
        prover_assignment.populate(
            left_blinded,
            right_blinded,
            domain_separator_bytes,
            &user_id,
            left_attempts,
            right_attempts,
            blinding_factor,
        );

        let proof = Groth16::prove(&pp_zk.proving_key, prover_assignment, rng)?;

        Ok(proof)
    }

    fn verify_left_token(
        pp_registration: &RegistrationPublicParameters<Bls12_377>,
        pk: &RegistrarPublicKey<Bls12_377>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
        blind_registration_attestation: &BlindRegistrationAttestation<Bls12_377>,
    ) -> Result<(), ARKEError> {
        let lhs = Bls12_377::pairing(blind_registration_attestation.left, pp_registration.g2_gen);
        let rhs = Bls12_377::pairing(blind_id.left, pk.left);

        match lhs == rhs {
            true => Ok(()),
            false => Err(ARKEError::InvalidCredentials),
        }
    }

    fn verify_right_token(
        pp_registration: &RegistrationPublicParameters<Bls12_377>,
        pk: &RegistrarPublicKey<Bls12_377>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
        blind_registration_attestation: &BlindRegistrationAttestation<Bls12_377>,
    ) -> Result<(), ARKEError> {
        let lhs = Bls12_377::pairing(pp_registration.g1_gen, blind_registration_attestation.right);
        let rhs = Bls12_377::pairing(pk.right, blind_id.right);

        match lhs == rhs {
            true => Ok(()),
            false => Err(ARKEError::InvalidCredentials),
        }
    }

    fn verify_blind_id_proof(
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
        registrar_domain: &[u8],
    ) -> Result<(), ARKEError> {
        let public_inputs =
            Self::prepare_public_inputs_for_verification(blind_id, registrar_domain);

        // Verify proof
        match Groth16::verify(&pp_zk.verifying_key, &public_inputs, &blind_id.proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ARKEError::VerificationFailed),
            Err(e) => Err(ARKEError::SynthesisError(e)),
        }
    }

    fn prepare_public_inputs_for_verification(
        blind_id: &BlindID<Bls12_377, BW6_761>,
        domain_separator_bytes: &[u8],
    ) -> Vec<ark_bls12_377::Fq> {
        let processed_left = blind_id.left.to_field_elements().expect("");
        let processed_right = blind_id.right.to_field_elements().expect("");
        // let processed_domain_sep = &domain_sep.to_field_elements().expect("");
        let mut processed_domain_sep: Vec<ark_bls12_377::Fq> =
            bytes_le_to_bits_le(&domain_separator_bytes, 8 * domain_separator_bytes.len())
                .iter()
                .map(|&bit| bit.to_field_elements().expect(""))
                .flatten()
                .collect::<Vec<_>>();

        let mut public_inputs = vec![
            processed_left[0],
            processed_left[1],
            ark_bls12_377::Fq::one(),
            processed_right[0],
            processed_right[1],
            processed_right[2],
            processed_right[3],
            ark_bls12_377::Fq::one(),
            ark_bls12_377::Fq::zero(),
        ]; // values obtained by debugging, yet to figure out where these Ones come from

        public_inputs.append(&mut processed_domain_sep);

        public_inputs
    }

    pub fn verify_blind_extract_request(
        pp_registration: &RegistrationPublicParameters<Bls12_377>,
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        registrar_public_key: &RegistrarPublicKey<Bls12_377>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
        blind_registration_attestation: &BlindRegistrationAttestation<Bls12_377>,
        registrar_domain: &[u8],
    ) -> Result<(), ARKEError> {
        Self::verify_left_token(
            pp_registration,
            registrar_public_key,
            blind_id,
            blind_registration_attestation,
        )?;
        Self::verify_right_token(
            pp_registration,
            registrar_public_key,
            blind_id,
            blind_registration_attestation,
        )?;

        Self::verify_blind_id_proof(pp_zk, blind_id, registrar_domain)?;

        Ok(())
    }

    pub fn emit_blind_partial_key(
        issuer_partial_secret_key: &IssuerSecretKey<Bls12_377>,
        blind_id: &BlindID<Bls12_377, BW6_761>,
    ) -> BlindPartialSecretKey<Bls12_377> {
        BlindPartialSecretKey {
            left: blind_id
                .left
                .mul(issuer_partial_secret_key.value.into_repr()),
            right: blind_id
                .right
                .mul(issuer_partial_secret_key.value.into_repr()),
            index: issuer_partial_secret_key.index,
        }
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_377::Bls12_377;
    use ark_bw6_761::BW6_761;
    use ark_serialize::CanonicalSerialize;
    use ark_std::One;
    use rand::{distributions::Alphanumeric, thread_rng, CryptoRng, Rng};

    use crate::{
        random_id, BlindIDCircuitParameters, BlindPartialSecretKey, IssuancePublicParameters,
        IssuerPublicKey, IssuerSecretKey, PartialSecretKey, RegistrarPublicKey, RegistrarSecretKey,
        ThresholdObliviousIdNIKE, UserID, UserSecretKey,
    };

    type ArkeIdNIKE = ThresholdObliviousIdNIKE<Bls12_377, BW6_761>;

    pub fn get_user_secret_key<R: Rng + CryptoRng>(
        pp_zk: &BlindIDCircuitParameters<BW6_761>,
        issuance_pp: &IssuancePublicParameters<Bls12_377>,
        user_id: &UserID,
        threshold: usize,
        registrar_secret_key: &RegistrarSecretKey<Bls12_377>,
        registrar_public_key: &RegistrarPublicKey<Bls12_377>,
        registrar_domain: &[u8],
        issuers_secret_keys: &[IssuerSecretKey<Bls12_377>],
        issuers_public_keys: &[IssuerPublicKey<Bls12_377>],
        rng: &mut R,
    ) -> UserSecretKey<Bls12_377> {
        println!("    Registration");
        // Register our user
        let reg_attestation =
            ArkeIdNIKE::register(&registrar_secret_key, &user_id, registrar_domain).unwrap();

        // Blind the identifier and token
        println!("    Blinding (and proof)");
        let (blinding_factor, blind_id, blind_reg_attestation) =
            ArkeIdNIKE::blind(pp_zk, user_id, registrar_domain, &reg_attestation, rng).unwrap();

        // Obtain blind partial secret keys from t+1 honest authorities
        println!("    BlindPartialExtract (verify reg and proof)");
        let blind_partial_user_keys: Vec<BlindPartialSecretKey<Bls12_377>> = issuers_secret_keys
            .iter()
            .zip(issuers_public_keys.iter())
            .map(|(secret_key, _public_key)| {
                ArkeIdNIKE::blind_partial_extract(
                    &issuance_pp,
                    pp_zk,
                    &registrar_public_key,
                    secret_key,
                    &blind_id,
                    &blind_reg_attestation,
                    registrar_domain,
                )
                .unwrap()
            })
            .collect();

        // Unblind each partial key
        println!("    Unblind");
        let partial_user_keys: Vec<PartialSecretKey<Bls12_377>> = blind_partial_user_keys
            .iter()
            .map(|blind_partial_sk| ArkeIdNIKE::unblind(blind_partial_sk, &blinding_factor))
            .collect();

        // Combine the partial keys to obtain a user secret key
        println!("    Combine");
        let user_secret_key = ArkeIdNIKE::combine(&partial_user_keys, threshold).unwrap();

        user_secret_key
    }

    #[test]
    #[ignore]
    pub fn test_threshold_oblivious_id_nike_completeness() {
        let mut rng = thread_rng();

        // Test Parameters
        let threshold = 3;
        let number_of_participants = 10;
        let identifier_length = 8;
        let registrar_domain = b"registration";

        // Generate a random user ID
        let alice_id_string = random_id!(identifier_length);
        let alice_id = UserID::new(&alice_id_string);

        // Generate a random user ID
        let bob_id_string = random_id!(identifier_length);
        let bob_id = UserID::new(&bob_id_string);

        let num_of_domain_sep_bytes = registrar_domain.len();
        let num_of_identifier_bytes = alice_id.0.as_bytes().len();
        let num_of_blinding_factor_bits = ark_bls12_377::Fr::one().serialized_size() * 8;

        // Simulate the SNARK trusted setup
        println!("Running trusted setup");
        let pp_zk = ArkeIdNIKE::setup_blind_id_proof(
            num_of_domain_sep_bytes,
            num_of_identifier_bytes,
            num_of_blinding_factor_bits,
            &mut rng,
        )
        .unwrap();

        // Simulate the DKG between issuers
        println!("Running DKG");
        let (pp_issuance, honest_issuers_secret_keys, honest_issuers_public_keys) =
            ArkeIdNIKE::simulate_issuers_DKG(threshold, number_of_participants, &mut rng).unwrap();

        // Create a registration authority
        println!("Setup registration authority");
        let (_pp_registration, registrar_secret_key, registrar_public_key) =
            ArkeIdNIKE::setup_registration(&mut rng);

        // Compute Alice and Bob's respective user secret keys
        println!("Alice gets her private keys:");
        let alice_sk = get_user_secret_key(
            &pp_zk,
            &pp_issuance,
            &alice_id,
            threshold,
            &registrar_secret_key,
            &registrar_public_key,
            registrar_domain,
            &honest_issuers_secret_keys,
            &honest_issuers_public_keys,
            &mut rng,
        );

        println!("Bob gets his private keys:");
        let bob_sk = get_user_secret_key(
            &pp_zk,
            &pp_issuance,
            &bob_id,
            threshold,
            &registrar_secret_key,
            &registrar_public_key,
            registrar_domain,
            &honest_issuers_secret_keys,
            &honest_issuers_public_keys,
            &mut rng,
        );

        // Compute a shared seed
        println!("Alice computes shared");
        let alice_computes_shared_seed =
            ArkeIdNIKE::shared_key(&alice_sk, &alice_id, &bob_id, registrar_domain).unwrap();
        println!("Bob computes shared");
        let bob_computes_shared_seed =
            ArkeIdNIKE::shared_key(&bob_sk, &bob_id, &alice_id, registrar_domain).unwrap();

        assert_eq!(alice_computes_shared_seed, bob_computes_shared_seed)
    }
}
