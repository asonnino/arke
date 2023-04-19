use crate::{poseidon377_parameters, proof_gadgets::y_to_bit::YToBitGadget};

use super::HashToG1Gadget;

use ark_bls12_377::{
    constraints::PairingVar, Bls12_377, Fq as Bls12_377_Fq, G1Projective,
    Parameters as Bls12_377_Parameters,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, AffineCurve, ProjectiveCurve};
use ark_ff::BitIteratorLE;
use ark_r1cs_std::{
    boolean::Boolean,
    groups::bls12::G1Var,
    prelude::{AllocationMode, CurveVar, EqGadget},
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::r1cs::SynthesisError;
use ark_sponge::{constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar};

pub struct Poseidon377HashToG1Gadget {}

impl HashToG1Gadget<Bls12_377_Fq, Bls12_377, PairingVar> for Poseidon377HashToG1Gadget {
    fn enforce_hash_to_group(
        counter: UInt8<Bls12_377_Fq>,
        extra_data: &[UInt8<Bls12_377_Fq>],
        message: &[UInt8<Bls12_377_Fq>],
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        let poseidon_params = poseidon377_parameters();
        let mut sponge_var = PoseidonSpongeVar::new(counter.cs(), &poseidon_params);

        sponge_var.absorb(&counter)?;
        sponge_var.absorb(&extra_data)?;
        sponge_var.absorb(&message)?;

        let x_coordinate = sponge_var.squeeze_field_elements(1)?;
        let sign_bit = sponge_var.squeeze_bits(1)?;

        let point_before_cofactor =
            G1Var::<Bls12_377_Parameters>::new_variable_omit_prime_order_check(
                sponge_var.cs(),
                || {
                    let x_coordinate_value = x_coordinate[0].value()?;
                    let sign_bit_value = sign_bit[0].value()?;
                    let p = GroupAffine::get_point_from_x(x_coordinate_value, sign_bit_value)
                        .ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(p.into_projective())
                },
                AllocationMode::Witness,
            )?;

        // Check that the allocated point has the right x coordinate
        point_before_cofactor.x.enforce_equal(&x_coordinate[0])?;

        // check Y/sign bit
        point_before_cofactor
            .y_to_bit()?
            .enforce_equal(&sign_bit[0])?;

        let scaled_point = Self::scale_by_cofactor_g1(&point_before_cofactor)?;

        Ok(scaled_point)
    }
}

impl Poseidon377HashToG1Gadget {
    /// Checks that the result is equal to the given point
    /// multiplied by the cofactor in g1
    fn scale_by_cofactor_g1(
        p: &G1Var<Bls12_377_Parameters>,
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        // get the cofactor's bits
        let cofactor_bits = BitIteratorLE::new(G1Projective::COFACTOR)
            .map(Boolean::constant)
            .collect::<Vec<Boolean<Bls12_377_Fq>>>();

        // return p * cofactor
        let scaled = p.scalar_mul_le(cofactor_bits.iter())?;
        Ok(scaled)
    }
}

#[cfg(test)]
mod test {
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use ark_std::rand::{thread_rng, RngCore};

    use crate::{
        poseidon377_parameters,
        proof_gadgets::hash_to_g1::{
            poseidon377_hash_to_g1::Poseidon377HashToG1Gadget, HashToG1Gadget,
        },
        PoseidonTryAndIncrement,
    };

    #[test]
    fn test_hash_to_g1() {
        let mut rng = thread_rng();
        // test for various input sizes
        for length in &[10, 25, 50, 100, 200, 300] {
            // fill a buffer with random elements
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let mut extra_input = vec![0; *length];
            rng.fill_bytes(&mut extra_input);
            // check that they get hashed properly
            dbg!(length);
            hash_to_group(&input, &extra_input);
        }

        fn hash_to_group(input: &[u8], extra_input: &[u8]) {
            let poseidon_params = poseidon377_parameters();
            let sponge: PoseidonSponge<ark_bls12_377::Fq> =
                CryptographicSponge::new(&poseidon_params);
            let mut try_and_increment = PoseidonTryAndIncrement::new(sponge);
            let (expected_hash, attempt) = try_and_increment
                .hash_to_bls12_377_g1(input, extra_input)
                .unwrap();

            let cs: ConstraintSystemRef<ark_bls12_377::Fq> = ConstraintSystem::new_ref();
            let counter = UInt8::new_witness(cs.clone(), || Ok(attempt as u8)).unwrap();
            let input = input
                .iter()
                .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
                .collect::<Vec<_>>();
            let extra_input = extra_input
                .iter()
                .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
                .collect::<Vec<_>>();

            let hash =
                Poseidon377HashToG1Gadget::enforce_hash_to_group(counter, &extra_input, &input)
                    .unwrap();

            assert!(cs.is_satisfied().unwrap());
            assert_eq!(expected_hash, hash.value().unwrap());
        }
    }
}
