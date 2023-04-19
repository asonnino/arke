use ark_ec::AffineCurve;
use ark_std::{end_timer, start_timer};
use byteorder::WriteBytesExt;
use std::marker::PhantomData;

use crate::{hash_to_curve::hash_length, FixedLengthHash, HashError, HashToCurve};

// use ark_bls12_377::Parameters;
use ark_ec::models::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    SWModelParameters,
};
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;

pub const NUM_TRIES: u8 = 255;

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// <https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf>.
#[derive(Clone)]
pub struct TryAndIncrement<H, P> {
    _curve_params: PhantomData<P>,
    _hash_function: PhantomData<H>,
}

impl<H, P> HashToCurve<GroupProjective<P>> for TryAndIncrement<H, P>
where
    H: FixedLengthHash<Error = HashError>,
    P: SWModelParameters,
{
    fn hash(
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<GroupProjective<P>, HashError> {
        Self::hash_with_attempt(domain, message, extra_data).map(|res| res.0)
    }
}

impl<H, P> TryAndIncrement<H, P>
where
    H: FixedLengthHash<Error = HashError>,
    P: SWModelParameters,
{
    /// Hash with attempt takes the input, appends a counter
    pub fn hash_with_attempt(
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(GroupProjective<P>, usize), HashError> {
        let num_bytes = GroupAffine::<P>::zero().serialized_size();
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let candidate_hash = H::hash(
                domain,
                &[&counter, extra_data, message].concat(),
                hash_bytes,
            )?;

            if let Some(p) = GroupAffine::<P>::from_random_bytes(&candidate_hash[..num_bytes]) {
                end_timer!(hash_loop_time);

                let scaled = p.scale_by_cofactor();
                if scaled.is_zero() {
                    continue;
                }

                return Ok((scaled, c as usize));
            }
        }
        Err(HashError::HashToCurveError)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        hash_to_curve::try_and_increment::TryAndIncrement, Blake2Xs, FixedLengthHash, HashError,
        HashToCurve,
    };

    use ark_bls12_377::Parameters;
    use ark_ec::{bls12::Bls12Parameters, models::SWModelParameters};
    use rand::RngCore;

    #[test]
    fn blake2xs_to_g1() {
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G1Parameters, Blake2Xs>()
    }

    #[test]
    fn blake2xs_to_g2() {
        hash_to_curve_test::<<Parameters as Bls12Parameters>::G2Parameters, Blake2Xs>()
    }

    fn hash_to_curve_test<P: SWModelParameters, H: FixedLengthHash<Error = HashError>>() {
        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let _ = TryAndIncrement::<H, P>::hash(&b"domain"[..], &input, &b"extra"[..]).unwrap();
        }
    }
}
