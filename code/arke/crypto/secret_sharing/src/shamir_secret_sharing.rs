use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
    rand::Rng,
};

use crate::{SSError, SecretSharingScheme};

pub struct ShamirSecretSharing<F: Field> {
    _field: PhantomData<F>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretShare<F: Field> {
    pub value: F,
    pub index: usize,
}

impl<F: Field> SecretSharingScheme for ShamirSecretSharing<F> {
    type Error = SSError;
    type Secret = F;
    type SecretShare = SecretShare<F>;

    fn generate_shares<R: Rng>(
        secret: &Self::Secret,
        number_of_participants: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<Vec<Self::SecretShare>, Self::Error> {
        let degree = threshold - 1;

        // Create a random polynomial of degree t-1 and set the constant coefficient to be secret
        let mut sharing_polynomial = DensePolynomial::rand(degree, rng);
        sharing_polynomial.coeffs[0] = *secret;

        // Create shares by evaluating the polynomial at fixed points. We never evaluate the polynomial
        // at 0, otherwise we would leak the secret
        let mut secret_shares = Vec::new();
        for i in 1..number_of_participants + 1 {
            let value = sharing_polynomial.evaluate(&F::from(i as u64));
            let index = i - 1;
            secret_shares.push(SecretShare { value, index });
        }

        Ok(secret_shares)
    }

    fn combine_shares(
        shares: &[Self::SecretShare],
        threshold: usize,
    ) -> Result<Self::Secret, Self::Error> {
        if shares.len() < threshold {
            return Err(SSError::ThresholdNotMet);
        }

        let domain: Vec<F> = shares
            .iter()
            .map(|share| F::from((share.index + 1) as u64))
            .collect(); // we add one because the secret shares are computed over [1..number_of_participants+1]

        let zero = F::zero();
        let mut accumulator = zero;
        for (i, share) in shares.iter().enumerate() {
            let evaluated_lagrange_basis = eval_lagrange_basis(&domain, i, zero)?;
            accumulator.add_assign(share.value * evaluated_lagrange_basis);
        }

        Ok(accumulator)
    }
}

/// Evaluate the i-th Lagrange basis at a user-chosen point
pub fn eval_lagrange_basis<F: Field>(
    domain: &[F],
    basis_index: usize,
    eval_point: F,
) -> Result<F, SSError> {
    let x_i = *domain.get(basis_index).ok_or(SSError::IndexOutOfRange)?; // implicit range-check of `basis-index`

    // Initialise the numerator and denominator
    let mut numerator = F::one();
    let mut denominator = F::one();

    for (i, element) in domain.iter().enumerate() {
        if i != basis_index {
            numerator.mul_assign(eval_point - element);
            denominator.mul_assign(x_i - element);
        }
    }

    let inverse_denominator = denominator.inverse().ok_or(SSError::NoInverse)?;
    Ok(numerator.mul(inverse_denominator))
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
    use ark_std::rand::thread_rng;

    use crate::{SecretSharingScheme, ShamirSecretSharing};

    use super::eval_lagrange_basis;

    /// Test the lagrange basis calculator. We use a hand-derived example: f(x) = 65 + 15x over
    /// the domain (1, 2, 3, 4)
    #[test]
    fn test_lagrange_basis() {
        let coeffs = vec![Fr::from(65u64), Fr::from(15u64)];
        let poly = DensePolynomial::from_coefficients_vec(coeffs.clone());
        let domain = vec![Fr::from(1u64), Fr::from(2u64)];

        let y0 = poly.evaluate(&domain[0]);
        assert_eq!(y0, Fr::from(80u64));

        let y1 = poly.evaluate(&domain[1]);
        assert_eq!(y1, Fr::from(95u64));

        let l0_at_0 = eval_lagrange_basis(&domain, 0, Fr::from(0u64)).unwrap();
        let l1_at_0 = eval_lagrange_basis(&domain, 1, Fr::from(0u64)).unwrap();

        assert_eq!(coeffs[0], y0 * l0_at_0 + y1 * l1_at_0)
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let rng = &mut thread_rng();

        let n = 10;
        let t = 3;

        let secret = ark_bn254::Fr::rand(rng);

        let shares = ShamirSecretSharing::generate_shares(&secret, n, t, rng).unwrap();

        // Some sanity checks
        assert_eq!(shares.len(), n);
        shares
            .iter()
            .for_each(|share| assert_ne!(share.value, secret));

        let combined = ShamirSecretSharing::combine_shares(&shares[0..t], t).unwrap();

        assert_eq!(combined, secret)
    }
}
