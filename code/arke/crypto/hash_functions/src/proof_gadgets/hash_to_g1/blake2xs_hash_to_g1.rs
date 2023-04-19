use ark_bls12_377::{
    constraints::PairingVar, Bls12_377, Fq as Bls12_377_Fq, Parameters as Bls12_377_Parameters,
};
use ark_ec::{
    bls12::Bls12Parameters, short_weierstrass_jacobian::GroupAffine, AffineCurve, SWModelParameters,
};
use ark_ff::{BigInteger, BitIteratorLE, PrimeField};
use ark_r1cs_std::{
    eq::EqGadget,
    groups::{bls12::G1Var, CurveVar},
    prelude::{AllocationMode, Boolean},
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::{
    proof_gadgets::{
        direct_hasher::DirectHasherGadget, y_to_bit::YToBitGadget, SIGN_BIT_POSITION, X_BITS,
    },
    SIG_DOMAIN,
};

use super::HashToG1Gadget;

/// Sub-circuit to hash binary messages into a curve point. Uses the try-and-increment method.
pub struct Blake2HashToG1Gadget<P: Bls12Parameters, F: PrimeField> {
    parameters_type: PhantomData<P>,
    field_type: PhantomData<F>,
}

impl HashToG1Gadget<Bls12_377_Fq, Bls12_377, PairingVar>
    for Blake2HashToG1Gadget<Bls12_377_Parameters, Bls12_377_Fq>
{
    fn enforce_hash_to_group(
        counter: UInt8<Bls12_377_Fq>,
        extra_data: &[UInt8<Bls12_377_Fq>],
        message: &[UInt8<Bls12_377_Fq>],
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        let mut input = counter.to_bits_le()?;

        // add extra data to input
        for v in extra_data {
            input.extend_from_slice(&v.to_bits_le()?);
        }

        // add message to input
        for m in message {
            input.extend_from_slice(&m.to_bits_le()?);
        }

        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let xof_bits = DirectHasherGadget::enforce_hash(personalization, input, 512)?;

        let hash = Self::hash_to_bls12_377_g1(&xof_bits)?;

        Ok(hash)
    }
}

impl Blake2HashToG1Gadget<Bls12_377_Parameters, Bls12_377_Fq> {
    /// Receives the output of `DirectHasherGadget::enforce_hash` in Little Endian
    /// decodes the G1 point and then multiplies it by the curve's cofactor to
    /// get the hash
    fn hash_to_bls12_377_g1(
        xof_bits: &[Boolean<Bls12_377_Fq>],
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        let xof_bits = xof_bits.to_vec();

        let x_bits = &xof_bits[..X_BITS];
        let sign_bit = &xof_bits[SIGN_BIT_POSITION];

        let expected_point_before_cofactor =
            G1Var::<Bls12_377_Parameters>::new_variable_omit_prime_order_check(
                x_bits.cs(),
                || {
                    // if we're in setup mode, just return an error
                    if x_bits.cs().is_in_setup_mode() {
                        return Err(SynthesisError::AssignmentMissing);
                    }

                    // get the bits from the Boolean constraints
                    // we assume that these are already encoded as LE
                    let bits = x_bits
                        .iter()
                        .map(|x| x.value())
                        .collect::<Result<Vec<bool>, _>>()?;

                    let big = <Bls12_377_Fq as PrimeField>::BigInt::from_bits_le(&bits);

                    let x = Bls12_377_Fq::from_repr(big).ok_or(SynthesisError::Unsatisfiable)?;
                    let sign_bit_value = sign_bit.value()?;

                    let p = GroupAffine::get_point_from_x(x, sign_bit_value)
                        .ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(p.into_projective())
                },
                AllocationMode::Witness,
            )?;

        // Point compression on the G1 Gadget
        let (compressed_point, compressed_sign_bit): (
            Vec<Boolean<Bls12_377_Fq>>,
            Boolean<Bls12_377_Fq>,
        ) = {
            // Convert x to LE
            let bits: Vec<Boolean<Bls12_377_Fq>> = expected_point_before_cofactor.x.to_bits_le()?;

            // Get a constraint about the y point's sign
            let greatest_bit = expected_point_before_cofactor.y_to_bit()?;

            (bits, greatest_bit)
        };

        // Check point equal to itself after being compressed
        for (a, b) in compressed_point.iter().zip(x_bits.iter()) {
            a.enforce_equal(b)?;
        }

        compressed_sign_bit.enforce_equal(sign_bit)?;

        let scaled_point = Self::scale_by_cofactor_g1(&expected_point_before_cofactor)?;

        Ok(scaled_point)
    }

    /// Checks that the result is equal to the given point
    /// multiplied by the cofactor in g1
    fn scale_by_cofactor_g1(
        p: &G1Var<Bls12_377_Parameters>,
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        // get the cofactor's bits
        let cofactor_bits =
            BitIteratorLE::new(<Bls12_377_Parameters as Bls12Parameters>::G1Parameters::COFACTOR)
                .map(Boolean::constant)
                .collect::<Vec<Boolean<Bls12_377_Fq>>>();

        // return p * cofactor
        let scaled = p.scalar_mul_le(cofactor_bits.iter())?;
        Ok(scaled)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{Blake2Xs, TryAndIncrement};
    use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8};
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{thread_rng, RngCore};

    type Bls12377G1Params = <ark_bls12_377::Parameters as Bls12Parameters>::G1Parameters;
    type H1 = TryAndIncrement<Blake2Xs, Bls12377G1Params>;

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
    }

    fn hash_to_group(input: &[u8], extra_input: &[u8]) {
        let (expected_hash, attempt) =
            H1::hash_with_attempt(SIG_DOMAIN, input, extra_input).unwrap();

        let cs = ConstraintSystem::<ark_bls12_377::Fq>::new_ref();
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
        Blake2HashToG1Gadget::<ark_bls12_377::Parameters, ark_bls12_377::Fq>::enforce_hash_to_group(
                counter,
                &extra_input,
                &input,
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_hash, hash.value().unwrap());
    }
}
