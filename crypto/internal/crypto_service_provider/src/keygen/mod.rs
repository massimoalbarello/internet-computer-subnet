//! Utilities for key generation and key identifier generation

use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
use crate::key_id::KeyId;
use crate::types::{CspPop, CspPublicKey};
use crate::vault::api::CspTlsKeygenError;
use crate::Csp;
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey, PolynomialCommitment};
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_sha::Sha256;
use ic_crypto_sha::{Context, DomainSeparationContext};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError};
use ic_types::NodeId;
use std::convert::TryFrom;

pub use tls_keygen::tls_cert_hash_as_key_id;

const KEY_ID_DOMAIN: &str = "ic-key-id";
const COMMITMENT_KEY_ID_DOMAIN: &str = "ic-key-id-idkg-commitment";

#[cfg(test)]
mod tests;

impl CspKeyGenerator for Csp {
    fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<CspPublicKey, CryptoError> {
        match alg_id {
            AlgorithmId::MultiBls12_381 => {
                let (_key_id, csp_pk, _pop) = self.csp_vault.gen_key_pair_with_pop(alg_id)?;
                Ok(csp_pk)
            }
            _ => {
                let (_key_id, csp_pk) = self.csp_vault.gen_key_pair(alg_id)?;
                Ok(csp_pk)
            }
        }
    }
    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(CspPublicKey, CspPop), CryptoError> {
        let (_key_id, csp_pk, pop) = self.csp_vault.gen_key_pair_with_pop(algorithm_id)?;
        Ok((csp_pk, pop))
    }

    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<TlsPublicKeyCert, CryptoError> {
        let (_key_id, cert) =
            self.csp_vault
                .gen_tls_key_pair(node, not_after)
                .map_err(|e| match e {
                    CspTlsKeygenError::InvalidNotAfterDate {
                        message: msg,
                        not_after: date,
                    } => CryptoError::InvalidNotAfterDate {
                        message: msg,
                        not_after: date,
                    },
                    CspTlsKeygenError::InternalError {
                        internal_error: msg,
                    } => CryptoError::InternalError {
                        internal_error: msg,
                    },
                })?;
        Ok(cert)
    }
}

impl CspSecretKeyStoreChecker for Csp {
    fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CryptoError> {
        Ok(self.csp_vault.sks_contains(key_id)?)
    }

    fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> Result<bool, CryptoError> {
        // we calculate the key_id first to minimize locking time:
        let key_id = tls_cert_hash_as_key_id(cert);
        self.sks_contains(&key_id)
    }
}

/// Compute the key identifier of the given public key
pub fn public_key_hash_as_key_id(pk: &CspPublicKey) -> KeyId {
    bytes_hash_as_key_id(pk.algorithm_id(), pk.pk_bytes())
}

// KeyId is SHA256 computed on the bytes:
//     domain_separator | algorithm_id | size(pk_bytes) | pk_bytes
// where  domain_separator is DomainSeparationContext(KEY_ID_DOMAIN),
// algorithm_id is a 1-byte value, and size(pk_bytes) is the size of
// pk_bytes as u32 in BigEndian format.
fn bytes_hash_as_key_id(alg_id: AlgorithmId, bytes: &[u8]) -> KeyId {
    let mut hash =
        Sha256::new_with_context(&DomainSeparationContext::new(KEY_ID_DOMAIN.to_string()));
    hash.write(&[alg_id as u8]);
    let bytes_size = u32::try_from(bytes.len()).expect("type conversion error");
    hash.write(&bytes_size.to_be_bytes());
    hash.write(bytes);
    KeyId::from(hash.finish())
}

/// Compute the key identifier for a forward secure encryption public key
pub fn forward_secure_key_id(public_key: &CspFsEncryptionPublicKey) -> KeyId {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
        "KeyId from CspFsEncryptionPublicKey",
    ));
    let variant: &'static str = public_key.into();
    hash.write(DomainSeparationContext::new(variant).as_bytes());
    match public_key {
        CspFsEncryptionPublicKey::Groth20_Bls12_381(public_key) => {
            hash.write(public_key.as_bytes())
        }
    }
    KeyId::from(hash.finish())
}

/// Compute the key identifier for a MEGa encryption public key
pub fn mega_key_id(public_key: &MEGaPublicKey) -> KeyId {
    match public_key.curve_type() {
        EccCurveType::K256 => bytes_hash_as_key_id(
            AlgorithmId::ThresholdEcdsaSecp256k1,
            &public_key.serialize(),
        ),
        c => panic!("unsupported curve: {:?}", c),
    }
}

pub fn commitment_key_id(commitment: &PolynomialCommitment) -> KeyId {
    let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
        COMMITMENT_KEY_ID_DOMAIN.to_string(),
    ));
    let commitment_encoding = commitment.stable_representation();
    hash.write(&(commitment_encoding.len() as u64).to_be_bytes());
    hash.write(&commitment_encoding);
    KeyId::from(hash.finish())
}

mod tls_keygen {
    use super::*;

    /// Create a key identifier by hashing the bytes of the certificate
    pub fn tls_cert_hash_as_key_id(cert: &TlsPublicKeyCert) -> KeyId {
        bytes_hash_as_key_id(AlgorithmId::Tls, cert.as_der())
    }
}

/// Some key related utils
pub mod utils {
    use ic_crypto_internal_types::encrypt::forward_secure::{
        CspFsEncryptionPop, CspFsEncryptionPublicKey,
    };
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;

    /// Form a protobuf structure of the public key and proof of possession
    pub fn dkg_dealing_encryption_pk_to_proto(
        pk: CspFsEncryptionPublicKey,
        pop: CspFsEncryptionPop,
    ) -> PublicKeyProto {
        match (pk, pop) {
            (
                CspFsEncryptionPublicKey::Groth20_Bls12_381(fs_enc_pk),
                CspFsEncryptionPop::Groth20WithPop_Bls12_381(_),
            ) => PublicKeyProto {
                algorithm: AlgorithmIdProto::Groth20Bls12381 as i32,
                key_value: fs_enc_pk.as_bytes().to_vec(),
                version: 0,
                proof_data: Some(serde_cbor::to_vec(&pop).expect(
                    "Failed to serialize DKG dealing encryption key proof of possession (PoP) to CBOR",
                )),
            },
            _=> panic!("Unsupported types")
        }
    }
}
