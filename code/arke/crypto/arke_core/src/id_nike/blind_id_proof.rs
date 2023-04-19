use ark_bls12_377::{
    constraints::{G1Var, G2Var},
    Bls12_377,
};
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use hash_functions::proof_gadgets::{
    hash_to_g1::{poseidon377_hash_to_g1::Poseidon377HashToG1Gadget, HashToG1Gadget},
    hash_to_g2::{poseidon377_hash_to_g2::Poseidon377HashToG2Gadget, HashToG2Gadget},
};

use crate::UserID;

#[derive(Clone)]
pub struct BlindIDCircuit<E: PairingEngine> {
    // Instance
    left_blind_hash: Option<E::G1Projective>,
    right_blind_hash: Option<E::G2Projective>,
    domain_separator_bytes: Vec<Option<u8>>,

    // Witness
    my_id_bytes: Vec<Option<u8>>,
    left_hash_attempts: Option<u8>,
    right_hash_attempts: Option<u8>,
    blinding_factor_bits: Vec<Option<bool>>,
}

impl<E: PairingEngine> BlindIDCircuit<E> {
    pub fn empty(
        num_of_domain_sep_bytes: usize,
        num_of_identifier_bytes: usize,
        num_of_blinding_factor_bits: usize,
    ) -> Self {
        Self {
            left_blind_hash: None,
            right_blind_hash: None,
            domain_separator_bytes: vec![None; num_of_domain_sep_bytes],
            my_id_bytes: vec![None; num_of_identifier_bytes],
            left_hash_attempts: None,
            right_hash_attempts: None,
            blinding_factor_bits: vec![None; num_of_blinding_factor_bits],
        }
    }

    pub fn populate(
        &mut self,
        left_blind_hash: &E::G1Projective,
        right_blind_hash: &E::G2Projective,
        domain_separator: &[u8],
        my_id: &UserID,
        left_hash_attempts: usize,
        right_hash_attempts: usize,
        blinding_factor: &E::Fr,
    ) {
        self.left_blind_hash = Some(left_blind_hash.clone());
        self.right_blind_hash = Some(right_blind_hash.clone());
        self.domain_separator_bytes = domain_separator.iter().map(|&byte| Some(byte)).collect();
        self.my_id_bytes = my_id.0.bytes().map(|byte| Some(byte)).collect();
        self.left_hash_attempts = Some(left_hash_attempts as u8);
        self.right_hash_attempts = Some(right_hash_attempts as u8);
        self.blinding_factor_bits = blinding_factor
            .into_repr()
            .to_bits_le()
            .iter()
            .map(|&bit| Some(bit))
            .collect();
    }
}

impl ConstraintSynthesizer<ark_bls12_377::Fq> for BlindIDCircuit<Bls12_377> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ark_bls12_377::Fq>,
    ) -> Result<(), SynthesisError> {
        // allocate public variables
        let claimed_left_blinded = G1Var::new_input(cs.clone(), || {
            self.left_blind_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let claimed_right_blinded = G2Var::new_input(cs.clone(), || {
            self.right_blind_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let dom_sep = self
            .domain_separator_bytes
            .iter()
            .map(|byte| {
                UInt8::new_input(cs.clone(), || byte.ok_or(SynthesisError::AssignmentMissing))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // allocate witness variables
        let user_g1_hash_attempts = UInt8::new_witness(cs.clone(), || {
            self.left_hash_attempts
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let user_g2_hash_attempts = UInt8::new_witness(cs.clone(), || {
            self.right_hash_attempts
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let user_id = self
            .my_id_bytes
            .iter()
            .map(|byte| {
                UInt8::new_witness(cs.clone(), || byte.ok_or(SynthesisError::AssignmentMissing))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let blinding_factor = self
            .blinding_factor_bits
            .iter()
            .map(|bit| {
                Boolean::new_witness(cs.clone(), || bit.ok_or(SynthesisError::AssignmentMissing))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Enforce hashes
        let hash_left = Poseidon377HashToG1Gadget::enforce_hash_to_group(
            user_g1_hash_attempts,
            &dom_sep,
            &user_id,
        )?;
        let hash_right = Poseidon377HashToG2Gadget::enforce_hash_to_group(
            user_g2_hash_attempts,
            &dom_sep,
            &user_id,
        )?;

        // Blind values
        let left_blinded = hash_left.scalar_mul_le(blinding_factor.iter())?;
        let right_blinded = hash_right.scalar_mul_le(blinding_factor.iter())?;

        // Check equality
        claimed_left_blinded.enforce_equal(&left_blinded)?;
        claimed_right_blinded.enforce_equal(&right_blinded)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{BlindIDCircuit, UserID};
    use ark_bls12_377::{Fq, Fr};
    use ark_ec::ProjectiveCurve;
    use ark_ff::{PrimeField, UniformRand};
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisMode,
    };
    use rand::{thread_rng, Rng};

    #[test]
    #[ignore]
    fn test_blind_id_circuit_setup() {
        let mut rng = thread_rng();

        let mut domain_sep = [0u8; 4];
        rng.fill(&mut domain_sep);

        // initialise the constraint system
        let cs: ConstraintSystemRef<Fq> = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);

        // initialise circuit
        let num_of_domain_sep_bytes = 4;
        let num_of_identifier_bytes = 10;
        let num_of_blinding_factor_bits = 256;

        let circuit: BlindIDCircuit<ark_bls12_377::Bls12_377> = BlindIDCircuit::empty(
            num_of_domain_sep_bytes,
            num_of_identifier_bytes,
            num_of_blinding_factor_bits,
        );

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        println!("Number of constraints: {}\n", cs.num_constraints());

        // // Check satisfied
        // assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[ignore]
    fn test_blind_id_circuit_satisfied() {
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
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
        });

        // initialise circuit
        let num_of_domain_sep_bytes = 4;
        let num_of_identifier_bytes = 10;
        let num_of_blinding_factor_bits = 256;

        let mut circuit: BlindIDCircuit<ark_bls12_377::Bls12_377> = BlindIDCircuit::empty(
            num_of_domain_sep_bytes,
            num_of_identifier_bytes,
            num_of_blinding_factor_bits,
        );
        circuit.populate(
            &left_blinded,
            &right_blinded,
            &domain_sep,
            &user_id,
            hashed.g1.attempts,
            hashed.g2.attempts,
            &blinding_factor,
        );

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
