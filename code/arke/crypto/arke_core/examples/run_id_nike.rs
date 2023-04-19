//! An example running the Threshold Oblivious ID-NIKE between users Alice and Bob.
//! This example uses a Groth16 SNARK over the BW6-761 curves and is quite slow. We recommend to
//! only run this in release mode.

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use rand::{distributions::Alphanumeric, thread_rng, CryptoRng, Rng};

use arke_core::{
    random_id, BlindIDCircuitParameters, BlindPartialSecretKey, IssuancePublicParameters,
    IssuerPublicKey, IssuerSecretKey, PartialSecretKey, RegistrarPublicKey, RegistrarSecretKey,
    ThresholdObliviousIdNIKE, UserID, UserSecretKey,
};

type ArkeIdNIKE = ThresholdObliviousIdNIKE<Bls12_377, BW6_761>;

/// Total number of participants
const NUMBER_OF_PARTICIPANTS: usize = 10;

/// Maximum number of dishonest key-issuing authorities that the system can tolerate
const THRESHOLD: usize = 3;

/// Number of characters in an identifier
const IDENTIFIER_STRING_LENGTH: usize = 8;

/// Domain identifier for the registration authority of this example
const REGISTRAR_DOMAIN: &'static [u8] = b"registration";

fn main() {
    let mut rng = thread_rng();

    // Generate a random user ID
    let alice_id_string = random_id!(IDENTIFIER_STRING_LENGTH);
    let alice_id = UserID::new(&alice_id_string);

    // Generate a random user ID
    let bob_id_string = random_id!(IDENTIFIER_STRING_LENGTH);
    let bob_id = UserID::new(&bob_id_string);

    let num_of_domain_sep_bytes = REGISTRAR_DOMAIN.len();
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
        ArkeIdNIKE::simulate_issuers_DKG(THRESHOLD, NUMBER_OF_PARTICIPANTS, &mut rng).unwrap();

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
        THRESHOLD,
        &registrar_secret_key,
        &registrar_public_key,
        REGISTRAR_DOMAIN,
        &honest_issuers_secret_keys,
        &honest_issuers_public_keys,
        &mut rng,
    );

    println!("Bob gets his private keys:");
    let bob_sk = get_user_secret_key(
        &pp_zk,
        &pp_issuance,
        &bob_id,
        THRESHOLD,
        &registrar_secret_key,
        &registrar_public_key,
        REGISTRAR_DOMAIN,
        &honest_issuers_secret_keys,
        &honest_issuers_public_keys,
        &mut rng,
    );

    // Compute a shared seed
    let alice_computes_shared_seed =
        ArkeIdNIKE::shared_key(&alice_sk, &alice_id, &bob_id, REGISTRAR_DOMAIN).unwrap();
    let mut alice_seed_bytes = Vec::new();
    alice_computes_shared_seed
        .serialize(&mut alice_seed_bytes)
        .unwrap();
    println!("Alice computes shared seed: {:?}\n", alice_seed_bytes);

    let bob_computes_shared_seed =
        ArkeIdNIKE::shared_key(&bob_sk, &bob_id, &alice_id, REGISTRAR_DOMAIN).unwrap();
    let mut bob_seed_bytes = Vec::new();
    bob_computes_shared_seed
        .serialize(&mut bob_seed_bytes)
        .unwrap();
    println!("Bob computes shared seed: {:?}\n", bob_seed_bytes);

    assert_eq!(alice_computes_shared_seed, bob_computes_shared_seed);
    println!("\nThe seeds match!")
}

fn get_user_secret_key<R: Rng + CryptoRng>(
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
