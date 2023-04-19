use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use arke_core::{
    BlindID, BlindPartialSecretKey, BlindRegistrationAttestation, IssuerPublicKey, IssuerSecretKey,
    PartialSecretKey, PublicParameters, RegistrarPublicKey, ThresholdObliviousIdNIKE, UserID,
    UserSecretKey,
};
use serde::{de::Error, Deserialize, Serialize};

use crate::MessageResult;

#[derive(Debug)]
pub struct BlindIdWrap {
    pub inner: BlindID<Bls12_377, BW6_761>,
}

impl Serialize for BlindIdWrap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::new();
        self.inner
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize BlindID");
        serde_bytes::serialize(&buf, serializer)
    }
}

impl<'de> Deserialize<'de> for BlindIdWrap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let inner = BlindID::<Bls12_377, BW6_761>::deserialize_unchecked(buf.as_slice())
            .map_err(D::Error::custom)?;
        Ok(Self { inner })
    }
}

#[derive(Debug)]
pub struct BlindRegistrationAttestationWrap {
    pub inner: BlindRegistrationAttestation<Bls12_377>,
}

impl Serialize for BlindRegistrationAttestationWrap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::new();
        self.inner
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize BlindID");
        serde_bytes::serialize(&buf, serializer)
    }
}

impl<'de> Deserialize<'de> for BlindRegistrationAttestationWrap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let inner =
            BlindRegistrationAttestation::<Bls12_377>::deserialize_unchecked(buf.as_slice())
                .map_err(D::Error::custom)?;
        Ok(Self { inner })
    }
}

/// Message sent by the users to request the issuance of long-term credentials.
/// This request contains cryptographic material already attested by a recognized
/// registry authority.
#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsRequest {
    pub blind_id: BlindIdWrap,
    pub blind_token: BlindRegistrationAttestationWrap,
    #[serde(with = "serde_bytes")]
    pub registrar_domain: Vec<u8>,
}

impl std::fmt::Display for CredentialsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "CR({:?})", self.blind_id.inner)
    }
}

impl CredentialsRequest {
    pub fn new(
        blind_id: BlindID<Bls12_377, BW6_761>,
        blind_token: BlindRegistrationAttestation<Bls12_377>,
        registrar_domain: Vec<u8>,
    ) -> Self {
        Self {
            blind_id: BlindIdWrap { inner: blind_id },
            blind_token: BlindRegistrationAttestationWrap { inner: blind_token },
            registrar_domain,
        }
    }

    pub fn verify(
        &self,
        pp: &PublicParameters<Bls12_377, BW6_761>,
        pk_reg: &RegistrarPublicKey<Bls12_377>,
    ) -> MessageResult<()> {
        ThresholdObliviousIdNIKE::verify_blind_extract_request(
            &pp.registration_params,
            &pp.zk_params,
            pk_reg,
            &self.blind_id.inner,
            &self.blind_token.inner,
            &self.registrar_domain,
        )?;

        Ok(())
    }
}

/// The partial long-term credentials issued by the authorities to the user.
#[derive(Debug)]
pub struct PartialCredentials {
    pub blind_partial_key: BlindPartialSecretKey<Bls12_377>,
}

impl Serialize for PartialCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::new();
        self.blind_partial_key
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize BlindPartialSecretKey");
        serde_bytes::serialize(&buf, serializer)
    }
}

impl<'de> Deserialize<'de> for PartialCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let blind_partial_key = BlindPartialSecretKey::deserialize_unchecked(buf.as_slice())
            .map_err(D::Error::custom)?;
        Ok(Self { blind_partial_key })
    }
}

impl std::fmt::Display for PartialCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self.blind_partial_key)
    }
}

impl PartialCredentials {
    pub fn new(
        authority_secret_key: &IssuerSecretKey<Bls12_377>,
        credential_request: &CredentialsRequest,
    ) -> Self {
        let blind_partial_key = ThresholdObliviousIdNIKE::emit_blind_partial_key(
            authority_secret_key,
            &credential_request.blind_id.inner,
        );

        Self { blind_partial_key }
    }

    pub fn verify(
        &self,
        pp: &PublicParameters<Bls12_377, BW6_761>,
        blinding_factor: &ark_bls12_377::Fr,
        user_id: &UserID,
        issuer_public_key: &IssuerPublicKey<Bls12_377>,
        registrar_domain: &[u8],
    ) -> MessageResult<()> {
        let unblinded = ThresholdObliviousIdNIKE::unblind(&self.blind_partial_key, blinding_factor);

        ThresholdObliviousIdNIKE::verify_partial_secret_key(
            &pp.issuance_params,
            user_id,
            issuer_public_key,
            registrar_domain,
            &unblinded,
        )?;

        Ok(())
    }
}

/// A user's long term credential (obtained by unblinding and combining PartialCredentials)
#[derive(Debug)]
pub struct Credentials {
    pub sk: UserSecretKey<Bls12_377>,
}

impl Serialize for Credentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::new();
        self.sk
            .serialize_unchecked(&mut buf)
            .expect("Failed to serialize BlindPartialSecretKey");
        serde_bytes::serialize(&buf, serializer)
    }
}

impl<'de> Deserialize<'de> for Credentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let sk = UserSecretKey::deserialize_unchecked(buf.as_slice()).map_err(D::Error::custom)?;
        Ok(Self { sk })
    }
}

impl std::fmt::Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self.sk)
    }
}

impl Credentials {
    pub fn new_with_verification(
        pp: &PublicParameters<Bls12_377, BW6_761>,
        user_id: &UserID,
        blinding_factors: &[ark_bls12_377::Fr],
        blind_partial_keys: &[PartialCredentials],
        issuer_public_keys: &[IssuerPublicKey<Bls12_377>],
        registrar_domain: &[u8],
    ) -> MessageResult<Self> {
        if blinding_factors.len() != blind_partial_keys.len() {
            return Err(crate::MessageError::MissingPartialKeys);
        }

        if blinding_factors.len() != issuer_public_keys.len() {
            return Err(crate::MessageError::MissingPartialKeys);
        }

        let unblinded: Vec<PartialSecretKey<_>> = blind_partial_keys
            .iter()
            .zip(blinding_factors.iter())
            .map(|(blind_key, blinding_factor)| {
                ThresholdObliviousIdNIKE::unblind(&blind_key.blind_partial_key, blinding_factor)
            })
            .collect();

        for (partial_key, issuer_pk) in unblinded.iter().zip(issuer_public_keys.iter()) {
            ThresholdObliviousIdNIKE::verify_partial_secret_key(
                &pp.issuance_params,
                user_id,
                issuer_pk,
                registrar_domain,
                partial_key,
            )?;
        }

        let full_secret_key = ThresholdObliviousIdNIKE::combine(&unblinded, pp.threshold)?;

        Ok(Self {
            sk: full_secret_key,
        })
    }

    pub fn new_unchecked(
        pp: &PublicParameters<Bls12_377, BW6_761>,
        blinding_factors: &[ark_bls12_377::Fr],
        blind_partial_keys: &[PartialCredentials],
    ) -> MessageResult<Self> {
        if blinding_factors.len() != blind_partial_keys.len() {
            return Err(crate::MessageError::MissingPartialKeys);
        }

        let unblinded: Vec<PartialSecretKey<_>> = blind_partial_keys
            .iter()
            .zip(blinding_factors.iter())
            .map(|(blind_key, blinding_factor)| {
                ThresholdObliviousIdNIKE::unblind(&blind_key.blind_partial_key, blinding_factor)
            })
            .collect();

        let full_secret_key = ThresholdObliviousIdNIKE::combine(&unblinded, pp.threshold)?;

        Ok(Self {
            sk: full_secret_key,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_377::Bls12_377;
    use ark_bw6_761::BW6_761;
    use arke_core::{export::TestSetup, ThresholdObliviousIdNIKE, UserID};
    use rand::thread_rng;

    use crate::{CredentialsRequest, PartialCredentials};

    use super::Credentials;

    type ArkeIdNIKE = ThresholdObliviousIdNIKE<Bls12_377, BW6_761>;
    type Setup = TestSetup<Bls12_377, BW6_761>;

    #[test]
    pub fn credentials_request() {
        let alice_id_string: String = "Alice".into();
        let alice_id = UserID::new(&alice_id_string);

        let committee_size = 10;
        let threshold = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            threshold,
            committee_size,
            vec![0u8],             // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        let registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &alice_id,
            &setup.registration_authorities[0].domain,
        )
        .unwrap();

        let (_blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
            &setup.pp.zk_params,
            &alice_id,
            &setup.registration_authorities[0].domain,
            &registration,
            &mut thread_rng(),
        )
        .unwrap();

        let request = CredentialsRequest::new(
            blind_id,
            blind_reg_attestation,
            setup.registration_authorities[0].domain.clone(),
        );

        request
            .verify(&setup.pp, &setup.registration_authorities[0].pk)
            .unwrap();
    }

    #[test]
    pub fn assemble_credential() {
        let alice_id_string: String = "Alice".into();
        let alice_id = UserID::new(&alice_id_string);

        let committee_size = 10;
        let faults = committee_size / 3;
        let setup = Setup::new_with_single_registrar(
            faults,
            committee_size,
            Vec::new(),            // registrar_domain
            alice_id_string.len(), // num_of_identifier_bytes
            &mut thread_rng(),
        )
        .unwrap();

        let registration = ArkeIdNIKE::register(
            &setup.registration_authorities[0].sk,
            &alice_id,
            &setup.registration_authorities[0].domain,
        )
        .unwrap();

        let (blinding_factor, blind_id, blind_reg_attestation) = ArkeIdNIKE::blind(
            &setup.pp.zk_params,
            &alice_id,
            &setup.registration_authorities[0].domain,
            &registration,
            &mut thread_rng(),
        )
        .unwrap();

        let request = CredentialsRequest::new(
            blind_id,
            blind_reg_attestation,
            setup.registration_authorities[0].domain.clone(),
        );

        let threshold = faults + 1;
        let partial_credentials: Vec<_> = setup
            .key_issuing_authorities
            .iter()
            .take(threshold)
            .map(|authority| PartialCredentials::new(&authority.sk, &request))
            .collect();

        for (partial_cred, authority) in partial_credentials
            .iter()
            .zip(setup.key_issuing_authorities.iter())
        {
            partial_cred
                .verify(
                    &setup.pp,
                    &blinding_factor,
                    &UserID::new(&alice_id_string),
                    &authority.pk,
                    &setup.registration_authorities[0].domain,
                )
                .unwrap();
        }

        let _alice_secret_key = Credentials::new_unchecked(
            &setup.pp,
            &vec![blinding_factor.clone(); 4],
            &partial_credentials,
        )
        .unwrap();
    }
}
