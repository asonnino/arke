use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::One;
use rand::{CryptoRng, Rng};

use crate::{
    utils::string_length_to_byte_length, ARKEError, IssuerPublicKey, IssuerSecretKey,
    PublicParameters, RegistrarPublicKey, RegistrarSecretKey, ThresholdObliviousIdNIKE,
};

/// A setup for testing. It contains:
/// - the public and private keys for key-issuing authorities
/// - the public, private keys and domain name for registration authorities
/// - the trusted setup for the ID blinding SNARK
/// All public parameters are bundled into `pp`.
///
/// WARNING: should not be used in production
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct TestSetup<ECompute: PairingEngine, EProve: PairingEngine> {
    pub pp: PublicParameters<ECompute, EProve>,
    pub key_issuing_authorities: Vec<KeyIssuingAuthority<ECompute>>,
    pub registration_authorities: Vec<RegistrationAuthority<ECompute>>,
    pub identifier_string_length: usize,
}

impl TestSetup<Bls12_377, BW6_761> {
    pub fn new_with_single_registrar<R: Rng + CryptoRng>(
        threshold: usize,
        number_of_participants: usize,
        registrar_domain: Vec<u8>,
        identifier_string_length: usize,
        rng: &mut R,
    ) -> Result<TestSetup<Bls12_377, BW6_761>, ARKEError> {
        let (pp_issuance, honest_auth_sk, honest_auth_pk) =
            ThresholdObliviousIdNIKE::simulate_issuers_DKG(threshold, number_of_participants, rng)?;

        let honest_authorities: Vec<KeyIssuingAuthority<_>> = honest_auth_sk
            .iter()
            .zip(honest_auth_pk.iter())
            .map(|(&sk, &pk)| KeyIssuingAuthority { sk, pk })
            .collect();

        let (pp_registration, registrar_sk, registrar_pk) =
            ThresholdObliviousIdNIKE::setup_registration(rng);

        let registration_authority = RegistrationAuthority {
            domain: registrar_domain,
            sk: registrar_sk,
            pk: registrar_pk,
        };

        let num_of_domain_sep_bytes = registration_authority.domain.len();
        let pp_zk = ThresholdObliviousIdNIKE::setup_blind_id_proof(
            num_of_domain_sep_bytes,
            string_length_to_byte_length(identifier_string_length),
            ark_bls12_377::Fr::one().serialized_size() * 8,
            rng,
        )?;

        let public_parameters = PublicParameters {
            threshold: threshold,
            registration_params: pp_registration,
            issuance_params: pp_issuance,
            zk_params: pp_zk,
        };

        let test_setup = TestSetup {
            pp: public_parameters,
            key_issuing_authorities: honest_authorities,
            registration_authorities: vec![registration_authority],
            identifier_string_length,
        };

        Ok(test_setup)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyIssuingAuthority<E: PairingEngine> {
    pub sk: IssuerSecretKey<E>,
    pub pk: IssuerPublicKey<E>,
}

#[derive(Clone, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RegistrationAuthority<E: PairingEngine> {
    pub domain: Vec<u8>,
    pub sk: RegistrarSecretKey<E>,
    pub pk: RegistrarPublicKey<E>,
}
