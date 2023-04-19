//! An example running the Threshold Oblivious ID-NIKE between users Alice and Bob.
//! This example uses a Groth16 SNARK over the BW6-761 curves and is quite slow. We recommend to
//! only run this in release mode.

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_serialize::CanonicalSerialize;
use rand::{distributions::Alphanumeric, thread_rng, CryptoRng, Rng};

use arke_core::{
    export::{KeyIssuingAuthority, RegistrationAuthority, TestSetup},
    random_id, BlindPartialSecretKey, PartialSecretKey, PublicParameters, ThresholdObliviousIdNIKE,
    UserID, UserSecretKey,
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

    let num_of_identifier_bytes = alice_id.0.as_bytes().len();

    let test_setup = TestSetup::new_with_single_registrar(
        THRESHOLD,
        NUMBER_OF_PARTICIPANTS,
        REGISTRAR_DOMAIN.to_vec(),
        num_of_identifier_bytes,
        &mut rng,
    )
    .unwrap();

    // Compute Alice and Bob's respective user secret keys
    println!("Alice gets her private keys:");
    let alice_sk = get_user_secret_key(
        &test_setup.pp,
        &alice_id,
        THRESHOLD,
        &test_setup.registration_authorities[0],
        &test_setup.key_issuing_authorities,
        &mut rng,
    );

    println!("Bob gets his private keys:");
    let bob_sk = get_user_secret_key(
        &test_setup.pp,
        &bob_id,
        THRESHOLD,
        &test_setup.registration_authorities[0],
        &test_setup.key_issuing_authorities,
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
    pp: &PublicParameters<Bls12_377, BW6_761>,
    user_id: &UserID,
    threshold: usize,
    registration_authority: &RegistrationAuthority<Bls12_377>,
    key_issuing_authorities: &[KeyIssuingAuthority<Bls12_377>],
    rng: &mut R,
) -> UserSecretKey<Bls12_377> {
    println!("    Registration");
    // Register our user
    let reg_attestation = ArkeIdNIKE::register(
        &registration_authority.sk,
        &user_id,
        &registration_authority.domain,
    )
    .unwrap();

    // Blind the identifier and token
    println!("    Blinding (and proof)");
    let (blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
        &pp.zk_params,
        user_id,
        &registration_authority.domain,
        &reg_attestation,
        rng,
    )
    .unwrap();

    // Obtain blind partial secret keys from t+1 honest authorities
    println!("    BlindPartialExtract (verify reg and proof)");
    let blind_partial_user_keys: Vec<BlindPartialSecretKey<Bls12_377>> = key_issuing_authorities
        .iter()
        .map(|auth| {
            ArkeIdNIKE::blind_partial_extract(
                &pp.registration_params,
                &pp.zk_params,
                &registration_authority.pk,
                &auth.sk,
                &blind_id,
                &blind_reg_attestation,
                &registration_authority.domain,
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
