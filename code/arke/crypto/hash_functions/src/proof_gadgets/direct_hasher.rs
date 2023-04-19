use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::proof_gadgets::blake2s::{
    blake2_as_crh_params, blake2xs_params, evaluate_blake2s_with_parameters,
};

/// Given `n` bytes, it returns the value rounded to the nearest multiple of 256 bits (in bytes)
/// e.g. 1. given 48 = 384 bits, it will return 64 bytes (= 512 bits)
///      2. given 96 = 768 bits, it will return 96 bytes (no rounding needed since 768 is already a
///         multiple of 256)
pub fn hash_length(n: usize) -> usize {
    let bits = (n * 8) as f64 / 256.0;
    let rounded_bits = bits.ceil() * 256.0;
    rounded_bits as usize / 8
}

pub struct DirectHasherGadget<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField> DirectHasherGadget<F> {
    pub fn enforce_crh(
        domain: [u8; 8],
        message: Vec<Boolean<F>>,
        hash_length_in_bits: u16,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let blake2s_parameters = blake2_as_crh_params(hash_length_in_bits, 0, domain);

        let crh_bits: Vec<_> =
            evaluate_blake2s_with_parameters(&message, &blake2s_parameters.parameters())?
                .iter()
                .flat_map(|integer| integer.to_bits_le())
                .collect();

        Ok(crh_bits)
    }

    pub fn enforce_xof(
        domain: [u8; 8],
        hashed_message: Vec<Boolean<F>>,
        output_size_in_bits: u16,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Blake2s outputs 256 bit hashes so the desired output hash length
        // must be a multiple of that.
        assert_eq!(output_size_in_bits % 256, 0, "invalid hash length size");
        let iterations = output_size_in_bits / 256;
        let mut xof_bits = Vec::new();
        // Run Blake on the message N times, each time offset by `i`
        // to get a `hash_length` hash. The hash is in LE.
        for i in 0..iterations {
            let blake2s_parameters = blake2xs_params(output_size_in_bits, i.into(), domain);

            let xof_result = evaluate_blake2s_with_parameters(
                &hashed_message,
                &blake2s_parameters.parameters(),
            )?;

            // convert hash result to LE bits
            let xof_bits_i = xof_result
                .into_iter()
                .map(|n| n.to_bits_le())
                .flatten()
                .collect::<Vec<Boolean<_>>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }
        Ok(xof_bits)
    }

    pub fn enforce_hash(
        domain: [u8; 8],
        message: Vec<Boolean<F>>,
        hash_length_in_bits: u16,
    ) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let prepared_message = Self::enforce_crh(domain, message, hash_length_in_bits)?;
        Self::enforce_xof(domain, prepared_message, hash_length_in_bits)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{utils::bits_le_to_bytes_le, Blake2Xs, FixedLengthHash};
    use ark_ff::Zero;
    use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8, R1CSVar, ToBitsGadget};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use rand::{thread_rng, RngCore};

    const SIG_DOMAIN: &[u8] = b"ULforxof";

    #[test]
    fn test_hash_output() {
        let mut rng = thread_rng();
        // test for various input sizes
        for length in &[10, 25, 50, 100, 200, 300] {
            // fill a buffer with random elements
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            // check that they get hashed properly
            // dbg!(length);
            check_hash_outputs(&input);
        }
    }

    fn check_hash_outputs(input: &[u8]) {
        let num_bytes = ark_bls12_377::G1Affine::zero().serialized_size();
        let hash_bytes = hash_length(num_bytes);

        let expected_hash = Blake2Xs::hash(SIG_DOMAIN, input, hash_bytes).unwrap();

        let cs = ConstraintSystem::<ark_bls12_377::Fq>::new_ref();
        let input = input
            .iter()
            .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
            .collect::<Vec<_>>();

        let mut message: Vec<Boolean<_>> = Vec::new();
        // add message to input
        for m in input {
            message.extend_from_slice(&m.to_bits_le().unwrap());
        }

        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let hashed_bits =
            DirectHasherGadget::enforce_hash(personalization, message, (hash_bytes * 8) as u16)
                .unwrap();

        let bits = hashed_bits
            .iter()
            .map(|x| x.value())
            .collect::<Result<Vec<bool>, _>>()
            .unwrap();

        // convert the crh bits to bytes
        let hash_in_bytes = bits_le_to_bytes_le(&bits);

        assert_eq!(expected_hash, hash_in_bytes)
    }

    #[test]
    #[ignore]
    fn test_crh_output() {
        let mut rng = thread_rng();
        // test for various input sizes
        for length in &[10, 25, 50, 100, 200, 300] {
            // fill a buffer with random elements
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            // check that they get hashed properly
            // dbg!(length);
            check_crh_outputs(&input);
        }
    }

    fn check_crh_outputs(input: &[u8]) {
        let num_bytes = ark_bls12_377::G1Affine::zero().serialized_size();
        let hash_bytes = hash_length(num_bytes);

        let expected_crh_bytes = Blake2Xs::crh(SIG_DOMAIN, input, hash_bytes).unwrap();

        let cs = ConstraintSystem::<ark_bls12_377::Fq>::new_ref();
        let input = input
            .iter()
            .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
            .collect::<Vec<_>>();

        let mut message: Vec<Boolean<_>> = Vec::new();
        // add message to input
        for m in input {
            message.extend_from_slice(&m.to_bits_le().unwrap());
        }

        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let crh_bits =
            DirectHasherGadget::enforce_crh(personalization, message, (hash_bytes * 8) as u16)
                .unwrap();

        let bits = crh_bits
            .iter()
            .map(|x| x.value())
            .collect::<Result<Vec<bool>, _>>()
            .unwrap();

        // convert the crh bits to bytes
        let crh_bytes = bits_le_to_bytes_le(&bits);

        assert_eq!(expected_crh_bytes, crh_bytes)
    }

    #[test]
    #[ignore]
    fn test_xof_output() {
        let mut rng = thread_rng();
        // test for various input sizes
        for input_length in &[300, 400] {
            // fill a buffer with random elements
            let mut input = vec![0; *input_length];
            rng.fill_bytes(&mut input);

            for factor in &[1, 2, 3] {
                let output_length = factor * 256;

                // check that they get hashed properly
                // dbg!(input_length, output_length);
                check_xof_outputs(&input, output_length);
            }
        }
    }

    fn check_xof_outputs(input: &[u8], output_size_in_bits: usize) {
        let expected_xof_bytes = Blake2Xs::xof(SIG_DOMAIN, input, output_size_in_bits / 8).unwrap();

        let cs = ConstraintSystem::<ark_bls12_377::Fq>::new_ref();
        let input = input
            .iter()
            .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
            .collect::<Vec<_>>();

        let mut message: Vec<Boolean<_>> = Vec::new();
        // add message to input
        for m in input {
            message.extend_from_slice(&m.to_bits_le().unwrap());
        }

        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let xof_bits =
            DirectHasherGadget::enforce_xof(personalization, message, output_size_in_bits as u16)
                .unwrap();

        let bits = xof_bits
            .iter()
            .map(|x| x.value())
            .collect::<Result<Vec<bool>, _>>()
            .unwrap();

        // convert the xof bits to bytes
        let xof_bytes = bits_le_to_bytes_le(&bits);

        assert_eq!(xof_bytes, expected_xof_bytes)
    }
}
