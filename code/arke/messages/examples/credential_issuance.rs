use std::{
    fs::File,
    io::{BufReader, Read},
};

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_serialize::CanonicalDeserialize;
use arke_core::{export::TestSetup, random_id, ThresholdObliviousIdNIKE, UserID};
use messages::{credentials::Credentials, CredentialsRequest, PartialCredentials};
use rand::{distributions::Alphanumeric, thread_rng, Rng};

type ArkeIdNIKE = ThresholdObliviousIdNIKE<Bls12_377, BW6_761>;

fn main() -> anyhow::Result<()> {
    let mut rng = thread_rng();

    // Load a setup that was generated for testing. This setup runs:
    // - a DKG for 10 key-issuing authorities with a threshold set to 3
    // - a public key and domain name for a single Registration authority
    // - a trusted setup for the token blinding proof
    // see the `TestSetup` documentation for more info.
    let setup_path = "examples/setup.example_data";
    let setup = import_setup(setup_path)?;

    // This example is hard-coded to query 4 authorities, we must check that
    // the threshold from the imported setup is less or equal to 3
    assert!(setup.pp.threshold <= 3);

    // Create a user Alice
    let alice_id_string = random_id!(setup.identifier_string_length);
    let alice_id = UserID::new(&alice_id_string);

    // Alice receives a registration token from the registration authority.
    // Note: we decided that this user/reg_auth interaction was out of scope for the demo
    let alice_reg_attestation = ArkeIdNIKE::register(
        &setup.registration_authorities[0].sk,
        &alice_id,
        &setup.registration_authorities[0].domain,
    )
    .unwrap();

    // Alice blinds her ID and registration attestation
    let (blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
        &setup.pp.zk_params,
        &alice_id,
        &setup.registration_authorities[0].domain,
        &alice_reg_attestation,
        &mut rng,
    )
    .unwrap();

    // Alice can now create her credentials request
    let alice_cred_request = CredentialsRequest::new(
        blind_id,
        blind_reg_attestation,
        setup.registration_authorities[0].domain.clone(),
    );

    // The credentials request gets sent to one of the key-issuing authorities.
    // Let's do authority0

    // authority0 verifies the credential request (here we check that the user was indeed registered and
    // that their ID is in the right domain. All blinded and in a SNARK.)
    alice_cred_request.verify(&setup.pp, &setup.registration_authorities[0].pk)?;
    // And respond with a partial key
    let authority0_response =
        PartialCredentials::new(&setup.key_issuing_authorities[0].sk, &alice_cred_request);

    // We repeat this process for authorities 1, 2 and 3
    let authority1_response =
        PartialCredentials::new(&setup.key_issuing_authorities[1].sk, &alice_cred_request);
    let authority2_response =
        PartialCredentials::new(&setup.key_issuing_authorities[2].sk, &alice_cred_request);
    let authority3_response =
        PartialCredentials::new(&setup.key_issuing_authorities[3].sk, &alice_cred_request);

    // The user can collect these partial responses
    let partial_creds = vec![
        authority0_response,
        authority1_response,
        authority2_response,
        authority3_response,
    ];

    // each partial credential can be verified for correctness using the authorities' public keys
    // Notice here that because all four authorities used the same CredentialRequest, there is only one blinding factor.
    // Alice could in fact send different requests to different authorities. She would need to keep track of which blinding factor
    // corresponds to which authority.
    let public_keys = vec![
        setup.key_issuing_authorities[0].pk,
        setup.key_issuing_authorities[1].pk,
        setup.key_issuing_authorities[2].pk,
        setup.key_issuing_authorities[3].pk,
    ];
    for (partial_cred, pk) in partial_creds.iter().zip(public_keys.iter()) {
        partial_cred.verify(
            &setup.pp,
            &blinding_factor,
            &alice_id,
            pk,
            &setup.registration_authorities[0].domain,
        )?;
    }

    // Alice can now combine these partial credentials to create a full credential
    let alice_secret_key =
        Credentials::new_unchecked(&setup.pp, &vec![blinding_factor; 4], &partial_creds)?;

    println!("{}", alice_secret_key);

    anyhow::Ok(())
}

fn import_setup(path: &str) -> anyhow::Result<TestSetup<Bls12_377, BW6_761>> {
    let source = File::open(path).unwrap();
    let mut reader = BufReader::new(source);
    let mut setup_bytes = Vec::new();
    reader.read_to_end(&mut setup_bytes).unwrap();

    let setup = TestSetup::<Bls12_377, BW6_761>::deserialize_unchecked(setup_bytes.as_slice())?;

    anyhow::Ok(setup)
}
