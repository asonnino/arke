use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::{PrimeField, QuadExtField, Zero};
use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};

use crate::{hash_to_curve::try_and_increment::NUM_TRIES, HashError};

pub struct PoseidonTryAndIncrement<F: PrimeField> {
    pub sponge: PoseidonSponge<F>,
}

impl<F: PrimeField> PoseidonTryAndIncrement<F> {
    pub fn new(sponge: PoseidonSponge<F>) -> Self {
        Self { sponge }
    }
}

impl PoseidonTryAndIncrement<ark_bls12_377::Fq> {
    pub fn hash_to_bls12_377_g1(
        &mut self,
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(ark_bls12_377::G1Projective, usize), HashError> {
        for c in 0..NUM_TRIES {
            // create a fresh sponge to prevent failed attempts from affecting the sponge state
            let mut fresh_sponge = self.sponge.clone();
            fresh_sponge.absorb(&c);
            fresh_sponge.absorb(&extra_data);
            fresh_sponge.absorb(&message);

            let candidate_hash: Vec<ark_bls12_377::Fq> = fresh_sponge.squeeze_field_elements(1);
            let sign_bit = fresh_sponge.squeeze_bits(1);

            if let Some(p) = GroupAffine::get_point_from_x(candidate_hash[0], sign_bit[0]) {
                let scaled = p.scale_by_cofactor();
                if scaled.is_zero() {
                    continue;
                }

                // keep the sponge that provided the successful output
                self.sponge = fresh_sponge;
                return Ok((scaled, c as usize));
            };
        }
        Err(HashError::HashToCurveError)
    }

    pub fn hash_to_bls12_377_g2(
        &mut self,
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(ark_bls12_377::G2Projective, usize), HashError> {
        for c in 0..NUM_TRIES {
            let mut fresh_sponge = self.sponge.clone();
            fresh_sponge.absorb(&c);
            fresh_sponge.absorb(&extra_data);
            fresh_sponge.absorb(&message);

            let sponge_output: Vec<ark_bls12_377::Fq> = fresh_sponge.squeeze_field_elements(2);
            let candidate_hash = QuadExtField::new(sponge_output[0], sponge_output[1]);
            let sign_bit = fresh_sponge.squeeze_bits(1);

            if let Some(p) = GroupAffine::get_point_from_x(candidate_hash, sign_bit[0]) {
                let scaled = p.scale_by_cofactor();
                if scaled.is_zero() {
                    continue;
                }

                // keep the sponge that provided the successful output
                self.sponge = fresh_sponge;
                return Ok((scaled, c as usize));
            };
        }
        Err(HashError::HashToCurveError)
    }
}

#[cfg(test)]
mod test {
    use crate::poseidon377_parameters;
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use rand::RngCore;

    use super::PoseidonTryAndIncrement;

    #[test]
    fn hash_to_g1_poseidon377() {
        let poseidon377_parameters = poseidon377_parameters();
        let sponge = PoseidonSponge::new(&poseidon377_parameters);
        let mut try_and_increment_hasher = PoseidonTryAndIncrement::new(sponge);

        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let (_point, _attempts): (ark_bls12_377::G1Projective, usize) =
                try_and_increment_hasher
                    .hash_to_bls12_377_g1(&input, &[])
                    .unwrap();
        }
    }

    #[test]
    fn hash_to_g2_poseidon377() {
        let poseidon377_parameters = poseidon377_parameters();
        let sponge = PoseidonSponge::new(&poseidon377_parameters);
        let mut try_and_increment_hasher = PoseidonTryAndIncrement::new(sponge);

        let mut rng = rand::thread_rng();
        for length in &[10, 25, 50, 100, 200, 300] {
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let (_point, _attempts): (ark_bls12_377::G2Projective, usize) =
                try_and_increment_hasher
                    .hash_to_bls12_377_g2(&input, &[])
                    .unwrap();
        }
    }
}
