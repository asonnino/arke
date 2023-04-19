use std::time::Instant;

use ark_bls12_377::{Fq, Fr};
use ark_bw6_761::BW6_761;
use ark_crypto_primitives::SNARK;
use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField, ToConstraintField, UniformRand, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use arke_core::{BlindIDCircuit, UserID};
use byte_unit::Byte;
use hash_functions::bytes_le_to_bits_le;
use rand::{thread_rng, Rng};

fn main() {
    let mut rng = thread_rng();

    let mut domain_sep = [0u8; 4];
    rng.fill(&mut domain_sep);

    let user_id = UserID::new("1234567890");
    let hashed = user_id.hash_bls12_377_poseidon(&domain_sep).unwrap();

    let blinding_factor = Fr::rand(&mut rng);

    let left_blinded = hashed.g1.hash.mul(blinding_factor.into_repr());
    let right_blinded = hashed.g2.hash.mul(blinding_factor.into_repr());

    // initialise the constraint system
    let cs: ConstraintSystemRef<Fq> = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Setup);

    // initialise circuit
    let num_of_domain_sep_bytes = 4;
    let num_of_identifier_bytes = 10;
    let num_of_blinding_factor_bits = 256;

    let empty_circuit: BlindIDCircuit<ark_bls12_377::Bls12_377> = BlindIDCircuit::empty(
        num_of_domain_sep_bytes,
        num_of_identifier_bytes,
        num_of_blinding_factor_bits,
    );

    // TRUSTED SETUP ------------------------------------------------------------------------
    // Initialize the proving system
    let start = Instant::now();
    let (pk, vk) =
        Groth16::<BW6_761>::circuit_specific_setup(empty_circuit.clone(), &mut rng).unwrap();
    let init_time = start.elapsed();
    println!(
        "Circuit-specific trusted setup: {} seconds",
        init_time.as_secs_f32()
    );
    println!(
        "Proving key size: {}\n",
        Byte::from_bytes(pk.serialized_size() as u128).get_appropriate_unit(false)
    );

    // PROVER --------------------------------------------------------------------------------
    // Populate circuit
    let mut prover_assignment = BlindIDCircuit::empty(
        num_of_domain_sep_bytes,
        num_of_identifier_bytes,
        num_of_blinding_factor_bits,
    );
    prover_assignment.populate(
        &left_blinded,
        &right_blinded,
        &domain_sep,
        &user_id,
        hashed.g1.attempts,
        hashed.g2.attempts,
        &blinding_factor,
    );

    // Generate proof
    let start = Instant::now();
    let proof = Groth16::prove(&pk, prover_assignment, &mut rng).unwrap();
    let proof_gen_time = start.elapsed();
    println!("Proof generated: {} seconds", proof_gen_time.as_secs_f32());
    println!(
        "Proof size: {}\n",
        Byte::from_bytes(proof.serialized_size() as u128).get_appropriate_unit(false)
    );

    // VERIFIER --------------------------------------------------------------------------------
    // compute public inputs
    let processed_left = left_blinded.to_field_elements().expect("");
    let processed_right = right_blinded.to_field_elements().expect("");
    let mut processed_domain_sep: Vec<Fq> = bytes_le_to_bits_le(&domain_sep, 8 * domain_sep.len())
        .iter()
        .map(|&bit| bit.to_field_elements().expect(""))
        .flatten()
        .collect::<Vec<_>>();

    let mut public_inputs = vec![
        processed_left[0],
        processed_left[1],
        Fq::one(),
        processed_right[0],
        processed_right[1],
        processed_right[2],
        processed_right[3],
        Fq::one(),
        Fq::zero(),
    ]; // values obtained by debugging. Affine coordinate and Fq::one(), followed by affine and affine coordinate with Fqe::one()
    public_inputs.append(&mut processed_domain_sep);

    // Verify proof
    match Groth16::verify(&vk, &public_inputs, &proof) {
        Ok(true) => println!("Proof is valid\n"),
        Ok(false) => println!("The proof was rejected\n"),
        Err(e) => println!("Error: {}", e),
    };
}
