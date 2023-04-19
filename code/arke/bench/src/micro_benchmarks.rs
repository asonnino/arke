use ark_bls12_377::{Bls12_377, FrParameters};
use ark_bw6_761::BW6_761;
use ark_ff::Fp256;
use arke_core::{export::TestSetup, RegistrationAttestation, ThresholdObliviousIdNIKE, UserID};
use messages::{credentials::Credentials, CredentialsRequest, PartialCredentials};
use rand::thread_rng;
use statistical::{mean, standard_deviation};
use tokio::time::Instant;

type ArkeIdNIKE = ThresholdObliviousIdNIKE<Bls12_377, BW6_761>;
type Setup = TestSetup<Bls12_377, BW6_761>;

/// Default size of the committee issuing the long-term credentials.
const DEFAULT_COMMITTEE_SIZE: usize = 10;
/// The default number of runs used to compute statistics.
const DEFAULT_RUNS: u64 = 10;
/// The default number measures to constitute a run (to smooth bootstrapping).
const DEFAULT_PRECISION: u64 = 5;

/// Run micro-benchmarks for every CPU-intensive operation.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let committee_size = match args.len() {
        x if x > 1 => args[1].parse().unwrap_or(DEFAULT_COMMITTEE_SIZE),
        _ => DEFAULT_COMMITTEE_SIZE,
    };
    println!("Starting micro-benchmarks:");

    // Run all micro-benchmarks.
    register_user(committee_size);
    create_credentials_request(committee_size);
    issue_partial_credential(committee_size);
    assemble_credential(committee_size);
}

/// Run a single micro-benchmark.
/// The `setup` function is executed before starting the timer and produces all the parameters needed for the
/// benchmark. The `run` function is executed multiple times using the setup data (as references).
fn bench<Setup, Run, Data, Result>(id: &str, setup: Setup, run: Run, num_runs: u64, precision: u64)
where
    Setup: FnOnce() -> Data,
    Run: Fn(&Data) -> Result,
{
    // Get the setup parameters.
    let inputs = setup();

    // Run the function to benchmark a number of times.
    let mut data = Vec::new();
    for _ in 0..num_runs {
        let now = Instant::now();
        for _ in 0..precision {
            let _result = run(&inputs);
        }
        let elapsed = now.elapsed().as_micros() as f64;
        data.push(elapsed / precision as f64);
    }

    // Display the results to stdout.
    println!(
        "  {:>7.2} +/- {:<5.2} ms {:.>50}",
        mean(&data) / 1_000.0,
        standard_deviation(&data, None) / 1_000.0,
        id
    );
}

fn register_user(committee_size: usize) {
    struct Data((Setup, String));

    let setup = || {
        let alice_id_string: String = "Alice".into();

        let threshold = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            threshold,
            committee_size,
            Vec::new(),            // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        Data((setup, alice_id_string))
    };

    let run = |data: &Data| {
        let Data((setup, alice_id_string)) = data;

        let _registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &UserID::new(&alice_id_string),
            &setup.registration_authorities[0].domain,
        )
        .unwrap();
    };

    bench("register user", setup, run, DEFAULT_RUNS, DEFAULT_PRECISION);
}

fn create_credentials_request(committee_size: usize) {
    struct Data((Setup, String, RegistrationAttestation<Bls12_377>));

    let setup = || {
        let alice_id_string: String = "Alice".into();

        let threshold = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            threshold,
            committee_size,
            Vec::new(),            // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        let registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &UserID::new(&alice_id_string),
            &setup.registration_authorities[0].domain,
        )
        .unwrap();

        Data((setup, alice_id_string, registration))
    };

    let run = |data: &Data| {
        let Data((setup, alice_id, registration)) = data;

        let (_blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
            &setup.pp.zk_params,
            &UserID::new(&alice_id),
            &setup.registration_authorities[0].domain,
            &registration,
            &mut thread_rng(),
        )
        .unwrap();

        let _alice_cred_request = CredentialsRequest::new(
            blind_id,
            blind_reg_attestation,
            setup.registration_authorities[0].domain.clone(),
        );
    };

    bench(
        "create credentials request",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}

fn issue_partial_credential(committee_size: usize) {
    struct Data((Setup, CredentialsRequest));

    let setup = || {
        let alice_id_string: String = "Alice".into();
        let alice_id = UserID::new(&alice_id_string);

        let threshold = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            threshold,
            committee_size,
            Vec::new(),            // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        let registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &alice_id,
            &setup.registration_authorities[0].domain,
        )
        .unwrap();

        let (_blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
            &setup.pp.zk_params,
            &alice_id,
            &setup.registration_authorities[0].domain,
            &registration,
            &mut thread_rng(),
        )
        .unwrap();

        let request = CredentialsRequest::new(
            blind_id,
            blind_reg_attestation,
            setup.registration_authorities[0].domain.clone(),
        );

        Data((setup, request))
    };

    let run = |data: &Data| {
        let Data((setup, request)) = data;

        request
            .verify(&setup.pp, &setup.registration_authorities[0].pk)
            .unwrap();

        let _authority0_response =
            PartialCredentials::new(&setup.key_issuing_authorities[0].sk, &request);
    };

    bench(
        "issue partial credential",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}

fn assemble_credential(committee_size: usize) {
    struct Data((Setup, Vec<PartialCredentials>, Fp256<FrParameters>, String));

    let setup = || {
        let alice_id_string: String = "Alice".into();
        let alice_id = UserID::new(&alice_id_string);

        let faults = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            faults,
            committee_size,
            Vec::new(),            // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        let registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &alice_id,
            &setup.registration_authorities[0].domain,
        )
        .unwrap();

        let (blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
            &setup.pp.zk_params,
            &alice_id,
            &setup.registration_authorities[0].domain,
            &registration,
            &mut thread_rng(),
        )
        .unwrap();

        let request = CredentialsRequest::new(
            blind_id,
            blind_reg_attestation,
            setup.registration_authorities[0].domain.clone(),
        );

        let threshold = faults + 1;
        let responses: Vec<_> = setup
            .key_issuing_authorities
            .iter()
            .take(threshold)
            .map(|authority| PartialCredentials::new(&authority.sk, &request))
            .collect();

        Data((setup, responses, blinding_factor, alice_id_string))
    };

    let run = |data: &Data| {
        let Data((setup, partial_credentials, blinding_factor, alice_id_string)) = data;

        for (partial_cred, authority) in partial_credentials
            .iter()
            .zip(setup.key_issuing_authorities.iter())
        {
            partial_cred
                .verify(
                    &setup.pp,
                    &blinding_factor,
                    &UserID::new(&alice_id_string),
                    &authority.pk,
                    &setup.registration_authorities[0].domain,
                )
                .unwrap();
        }

        let _alice_secret_key = Credentials::new_unchecked(
            &setup.pp,
            &vec![blinding_factor.clone(); 4],
            &partial_credentials,
        )
        .unwrap();
    };

    bench(
        "assemble credential",
        setup,
        run,
        DEFAULT_RUNS,
        DEFAULT_PRECISION,
    );
}
