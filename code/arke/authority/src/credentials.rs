use std::collections::HashMap;

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use arke_core::{IssuerSecretKey, PublicParameters, RegistrarPublicKey};
use messages::{AuthorityError, AuthorityResult, CredentialsRequest, PartialCredentials};

pub struct CredentialsIssuer {
    /// The public parameters to verify credentials requests.
    public_parameters: PublicParameters<Bls12_377, BW6_761>,
    /// Authorized registrars.
    registrars: HashMap<Vec<u8>, RegistrarPublicKey<Bls12_377>>,
    /// Secret key to issue credentials.
    credentials_key: IssuerSecretKey<Bls12_377>,
}

impl CredentialsIssuer {
    pub fn new(
        public_parameters: PublicParameters<Bls12_377, BW6_761>,
        registrars: HashMap<Vec<u8>, RegistrarPublicKey<Bls12_377>>,
        credentials_key: IssuerSecretKey<Bls12_377>,
    ) -> Self {
        Self {
            public_parameters,
            registrars,
            credentials_key,
        }
    }

    /// Issue long-term credentials to users.
    pub fn handle_credentials_request(
        &self,
        request: CredentialsRequest,
    ) -> AuthorityResult<PartialCredentials> {
        tracing::debug!("Processing {request:?}");

        // Ensure the request is valid.
        let registrar = &request.registrar_domain;
        let pk = match self.registrars.get(registrar) {
            Some(pk) => pk,
            None => return Err(AuthorityError::UnknownRegistrar(registrar.to_vec())),
        };
        request.verify(&self.public_parameters, pk)?;

        // Issue a partial credential.
        let credentials = PartialCredentials::new(&self.credentials_key, &request);
        tracing::debug!("Issued {credentials}");
        Ok(credentials)
    }
}
