//! File copied and adapted from a more recent version of arkworks (see https://github.com/arkworks-rs/crypto-primitives/blob/main/src/prf/blake2s/constraints.rs)
//! Can probably be removed with next release of arkworks.

use ark_crypto_primitives::prf::PRF;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use core::fmt::Debug;

pub mod blake2s;
pub mod direct_hasher;
pub mod hash_to_g1;
pub mod hash_to_g2;
pub mod y_to_bit;

// Zexe's upstream logic takes the sign bit from position 383.
pub const SIGN_BIT_POSITION: usize = 383;

// The bits from the hash which will be interpreted as the x coordinate of a group element
pub const X_BITS: usize = 377;

/// Split the bits at the half-point as done in https://github.com/arkworks-rs/algebra/blob/402e7f9603fca7a68b86baf296b6feaf904939f5/ff/src/fields/models/quadratic_extension.rs#L258
pub const SPLIT_AT: usize = 384;

pub const EXT_SIGN_BIT_POSITION: usize = 767;

pub trait PRFGadget<P: PRF, F: Field> {
    type OutputVar: EqGadget<F>
        + ToBytesGadget<F>
        + AllocVar<P::Output, F>
        + R1CSVar<F, Value = P::Output>
        + Clone
        + Debug;

    fn new_seed(cs: impl Into<Namespace<F>>, seed: &P::Seed) -> Vec<UInt8<F>>;

    fn evaluate(seed: &[UInt8<F>], input: &[UInt8<F>]) -> Result<Self::OutputVar, SynthesisError>;
}
