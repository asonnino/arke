use std::{fs::File, io::BufReader};

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use arke_core::export::TestSetup;
use rand::thread_rng;

/// Total number of participants
const NUMBER_OF_PARTICIPANTS: usize = 10;

/// Maximum number of dishonest key-issuing authorities that the system can tolerate
const THRESHOLD: usize = 3;

/// Number of bytes in an identifier
const IDENTIFIER_STRING_LENGTH: usize = 8;

/// Domain identifier for the registration authority of this example
const REGISTRAR_DOMAIN: &'static [u8] = b"registration";

fn main() {
    let mut rng = thread_rng();

    // Run the setup
    let test_setup = TestSetup::new_with_single_registrar(
        THRESHOLD,
        NUMBER_OF_PARTICIPANTS,
        REGISTRAR_DOMAIN.to_vec(),
        IDENTIFIER_STRING_LENGTH,
        &mut rng,
    )
    .unwrap();

    let path = "examples/setup.arke";

    // Serialize
    let mut test_setup_bytes = Vec::new();
    test_setup
        .serialize_unchecked(&mut test_setup_bytes)
        .unwrap();

    // Export to file
    export_setup(&test_setup_bytes, path);

    // Import from file
    let imported_bytes = import_setup(path);

    // Check that the bytes match
    assert_eq!(imported_bytes, test_setup_bytes);

    // Deserialize
    let recovered_setup =
        TestSetup::<Bls12_377, BW6_761>::deserialize_unchecked(imported_bytes.as_slice()).unwrap();

    assert_eq!(
        recovered_setup.key_issuing_authorities,
        test_setup.key_issuing_authorities
    );
}

fn export_setup(test_setup_bytes: &[u8], path: &str) {
    let mut output = File::create(path).unwrap();
    output.write_all(test_setup_bytes).unwrap();
}

fn import_setup(path: &str) -> Vec<u8> {
    let source = File::open(path).unwrap();
    let mut reader = BufReader::new(source);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();

    buffer
}
