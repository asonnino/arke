use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_r1cs_std::{prelude::PairingVar, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

// pub mod blake2xs_hash_to_g1;
pub mod poseidon377_hash_to_g1;

/// Build constraints for the Hash-to-G1 operation using the try and increment method.
pub trait HashToG1Gadget<ConstraintF: Field, E: PairingEngine, P: PairingVar<E, ConstraintF>> {
    fn enforce_hash_to_group(
        counter: UInt8<ConstraintF>,
        extra_data: &[UInt8<ConstraintF>],
        message: &[UInt8<ConstraintF>],
    ) -> Result<P::G1Var, SynthesisError>;
}
