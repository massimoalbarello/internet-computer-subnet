//! Type conversion utilities

use super::{
    CspPop, CspPublicCoefficients, CspPublicKey, CspSecretKey, CspSignature,
    MultiBls12_381_Signature, SigConverter, ThresBls12_381_Signature,
};
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as ecdsa_secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_secp256r1_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_rsa_pkcs1 as rsa;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::EphemeralKeySetBytes;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::dkg::EncryptionPublicKeyPop;
use ic_types::crypto::{AlgorithmId, CryptoError, UserPublicKey};
use std::convert::TryFrom;
use std::fmt;

pub mod dkg_id_to_key_id;

use crate::key_id::KeyId;
use ic_crypto_internal_multi_sig_bls12381::types::conversions::protobuf::PopBytesFromProtoError;
use ic_crypto_sha::{Context, DomainSeparationContext};
use openssl::sha::Sha256;

#[cfg(test)]
mod tests;

/// Create a key identifier from the public coefficients
// TODO (CRP-821): Tests - take the existing ones from classic DKG.
pub fn key_id_from_csp_pub_coeffs(csp_public_coefficients: &CspPublicCoefficients) -> KeyId {
    let mut hash = Sha256::new();
    hash.update(
        DomainSeparationContext::new("KeyId from threshold public coefficients").as_bytes(),
    );
    hash.update(
        &serde_cbor::to_vec(&csp_public_coefficients)
            .expect("Failed to serialize public coefficients"),
    );
    KeyId::from(hash.finish())
}

#[cfg(test)]
mod key_id_generation_stability_tests {
    use crate::key_id::KeyId;
    use crate::types::conversions::key_id_from_csp_pub_coeffs;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_1_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_2_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_3_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_4_PK;
    use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
    use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
    use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;

    #[derive(Debug)]
    struct TestCase<T: AsRef<[u8]>> {
        public_key: T,
        expected_key_id: T,
    }

    impl<T: AsRef<[u8]>> TestCase<T> {
        fn expected_key_id(&self) -> KeyId {
            KeyId::from(hex_to_bytes(&self.expected_key_id))
        }

        fn csp_public_coefficients(&self) -> CspPublicCoefficients {
            let raw_public_key = hex_to_bytes(&self.public_key);
            CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
                coefficients: vec![PublicKeyBytes(raw_public_key)],
            })
        }
    }

    fn hex_to_bytes<T: AsRef<[u8]>, const N: usize>(data: T) -> [u8; N] {
        hex::decode(data)
            .expect("error decoding hex")
            .try_into()
            .expect("wrong size of array")
    }

    #[test]
    fn should_key_id_from_csp_pub_coeffs_be_stable() {
        let tests = vec![
            TestCase {
                public_key: "9772c16106e9c70b2073dfe17989225d\
                d10f3adb675365fc6d833587ad4cbd3a\
                e692ad1e20679003f676b0b089e83feb\
                058b3e8b9fc9552e30787cb4a541a1c3\
                bf67a02e91fc648b2c19f4bb333e14c5\
                c73b9bfbc5ec56dadabb07ff15d45124",
                expected_key_id: "158626c7c78741000e9ab35970ff887c63fbc8596e9e40cb32472b67150be96d",
            },
            TestCase {
                public_key: TESTVEC_MULTI_BLS12_381_1_PK,
                expected_key_id: "b2174971f382200287319ee1680088c917a019cb9b1469105c3a5e42459844a3",
            },
            TestCase {
                public_key: TESTVEC_MULTI_BLS12_381_2_PK,
                expected_key_id: "b82b7a16e60e1b8a643eaccb79b192cfe047d32c85a8f757cdbf68d3e910d64f",
            },
            TestCase {
                public_key: TESTVEC_MULTI_BLS12_381_3_PK,
                expected_key_id: "3239d711728ed30d26a17f68523dec7e86b2496af00ae672733a7d245d5915a6",
            },
            TestCase {
                public_key: TESTVEC_MULTI_BLS12_381_4_PK,
                expected_key_id: "8df4243f903775f7b4c626c2e5554f0251baf69ab091cb7ce866b724b9eb4c2d",
            },
        ];

        for test in tests {
            assert_eq!(
                key_id_from_csp_pub_coeffs(&test.csp_public_coefficients()),
                test.expected_key_id(),
                "Error in test {:#?}",
                test
            )
        }
    }
}

impl From<&CspPublicKey> for AlgorithmId {
    fn from(public_key: &CspPublicKey) -> Self {
        match public_key {
            CspPublicKey::EcdsaP256(_) => AlgorithmId::EcdsaP256,
            CspPublicKey::EcdsaSecp256k1(_) => AlgorithmId::EcdsaSecp256k1,
            CspPublicKey::Ed25519(_) => AlgorithmId::Ed25519,
            CspPublicKey::MultiBls12_381(_) => AlgorithmId::MultiBls12_381,
            CspPublicKey::RsaSha256(_) => AlgorithmId::RsaSha256,
        }
    }
}

impl TryFrom<CspPublicKey> for UserPublicKey {
    type Error = CryptoError;
    fn try_from(pk: CspPublicKey) -> Result<Self, CryptoError> {
        match pk {
            CspPublicKey::EcdsaP256(pk) => Ok(UserPublicKey {
                key: pk.0.to_vec(),
                algorithm_id: AlgorithmId::EcdsaP256,
            }),
            CspPublicKey::Ed25519(pk) => Ok(UserPublicKey {
                key: pk.0.to_vec(),
                algorithm_id: AlgorithmId::Ed25519,
            }),
            _ => Err(CryptoError::InvalidArgument {
                message: format!(
                    "Unsupported conversion from CspPublicKey to UserPublicKey: {:?}",
                    pk
                ),
            }),
        }
    }
}

impl TryFrom<PublicKeyProto> for CspPublicKey {
    type Error = CryptoError;
    // TODO (CRP-540): move the key bytes from pk_proto.key_value to the
    //   resulting csp_pk (instead of copying/cloning them).
    fn try_from(pk_proto: PublicKeyProto) -> Result<Self, Self::Error> {
        match AlgorithmId::from(pk_proto.algorithm) {
            AlgorithmId::Ed25519 => {
                let public_key_bytes =
                    ed25519_types::PublicKeyBytes::try_from(&pk_proto).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::Ed25519,
                            key_bytes: Some(e.key_bytes),
                            internal_error: e.internal_error,
                        }
                    })?;
                Ok(CspPublicKey::Ed25519(public_key_bytes))
            }
            AlgorithmId::MultiBls12_381 => {
                let public_key_bytes =
                    multi_types::PublicKeyBytes::try_from(&pk_proto).map_err(|e| {
                        CryptoError::MalformedPublicKey {
                            algorithm: AlgorithmId::MultiBls12_381,
                            key_bytes: Some(e.key_bytes),
                            internal_error: e.internal_error,
                        }
                    })?;
                Ok(CspPublicKey::MultiBls12_381(public_key_bytes))
            }
            _ => Err(CryptoError::AlgorithmNotSupported {
                algorithm: AlgorithmId::from(pk_proto.algorithm),
                reason: "Could not convert to CspPublicKey".to_string(),
            }),
        }
    }
}

impl TryFrom<&PublicKeyProto> for CspPop {
    type Error = CspPopFromPublicKeyProtoError;

    fn try_from(pk_proto: &PublicKeyProto) -> Result<Self, Self::Error> {
        let pop_bytes = multi_types::PopBytes::try_from(pk_proto)?;
        Ok(CspPop::MultiBls12_381(pop_bytes))
    }
}

/// A problem while reading PoP from a public key protobuf
#[derive(Clone, PartialEq, Eq)]
pub enum CspPopFromPublicKeyProtoError {
    NoPopForAlgorithm {
        algorithm: AlgorithmId,
    },
    MissingProofData,
    MalformedPop {
        pop_bytes: Vec<u8>,
        internal_error: String,
    },
}
impl fmt::Debug for CspPopFromPublicKeyProtoError {
    /// Prints in a developer-friendly format.
    ///
    /// The standard rust encoding is used for all fields except the PoP, which
    /// is encoded as hex rather than arrays of integers.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CspPopFromPublicKeyProtoError::*;
        match self {
            NoPopForAlgorithm{ algorithm } => write!(f, "CspPopFromPublicKeyProtoError::NoPopForAlgorithm{{ algorithm: {:?} }}", algorithm),
            MissingProofData => write!(f, "CspPopFromPublicKeyProtoError::MissingProofData"),
            MalformedPop{ pop_bytes, internal_error } => write!(f, "CspPopFromPublicKeyProtoError::MalformedPop{{ pop_bytes: {:?}, internal_error: {} }}", hex::encode(&pop_bytes[..]), internal_error),
        }
    }
}

impl From<PopBytesFromProtoError> for CspPopFromPublicKeyProtoError {
    fn from(pop_bytes_from_proto_error: PopBytesFromProtoError) -> Self {
        match pop_bytes_from_proto_error {
            PopBytesFromProtoError::UnknownAlgorithm { algorithm } => {
                CspPopFromPublicKeyProtoError::NoPopForAlgorithm {
                    algorithm: AlgorithmId::from(algorithm),
                }
            }
            PopBytesFromProtoError::MissingProofData => {
                CspPopFromPublicKeyProtoError::MissingProofData
            }
            PopBytesFromProtoError::InvalidLength {
                pop_bytes,
                internal_error,
            } => CspPopFromPublicKeyProtoError::MalformedPop {
                pop_bytes,
                internal_error,
            },
        }
    }
}

// This is a temporary way to get to the raw bytes of CspPublicKey until
// we have consolidated the key/signatures types which will likely involve
// removing the CspPublicKey type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspPublicKey::EcdsaP256(bytes) => &bytes.0,
            CspPublicKey::EcdsaSecp256k1(bytes) => &bytes.0,
            CspPublicKey::Ed25519(bytes) => &bytes.0,
            CspPublicKey::MultiBls12_381(public_key_bytes) => &public_key_bytes.0,
            CspPublicKey::RsaSha256(public_key_bytes) => public_key_bytes.as_der(),
        }
    }
}

// This is a temporary way to get to the raw bytes of CspPop until
// we have consolidated the key/signatures types which will likely involve
// removing the CspPop type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspPop {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspPop::MultiBls12_381(sig_bytes) => &sig_bytes.0,
            CspPop::Secp256k1(sig_bytes) => &sig_bytes.0,
        }
    }
}

// This is a temporary way to get to the raw bytes of CspSignature until
// we have consolidated the key/signatures types which will likely involve
// removing the CspSignature type. Because this impl is temporary, there are
// no associated tests.
// TODO (CRP-218): Remove as part of CRP-218
impl AsRef<[u8]> for CspSignature {
    fn as_ref(&self) -> &[u8] {
        match self {
            CspSignature::EcdsaP256(bytes) => &bytes.0,
            CspSignature::EcdsaSecp256k1(bytes) => &bytes.0,
            CspSignature::Ed25519(bytes) => &bytes.0,
            CspSignature::MultiBls12_381(sig) => match sig {
                MultiBls12_381_Signature::Individual(sig_bytes) => &sig_bytes.0,
                MultiBls12_381_Signature::Combined(sig_bytes) => &sig_bytes.0,
            },
            CspSignature::ThresBls12_381(sig) => match sig {
                ThresBls12_381_Signature::Individual(sig_bytes) => &sig_bytes.0,
                ThresBls12_381_Signature::Combined(sig_bytes) => &sig_bytes.0,
            },
            CspSignature::RsaSha256(bytes) => bytes,
        }
    }
}

impl TryFrom<&UserPublicKey> for CspPublicKey {
    type Error = CryptoError;

    fn try_from(user_public_key: &UserPublicKey) -> Result<Self, Self::Error> {
        match user_public_key.algorithm_id {
            AlgorithmId::Ed25519 => {
                const PUBKEY_LEN: usize = ed25519_types::PublicKeyBytes::SIZE;

                if user_public_key.key.len() != PUBKEY_LEN {
                    return Err(CryptoError::MalformedPublicKey {
                        algorithm: AlgorithmId::Ed25519,
                        key_bytes: Some(user_public_key.key.to_owned()),
                        internal_error: format!(
                            "Invalid length: Expected Ed25519 public key with {} bytes but got {} bytes",
                            PUBKEY_LEN,
                            user_public_key.key.len()
                        ),
                    });
                }
                let mut bytes: [u8; PUBKEY_LEN] = [0; PUBKEY_LEN];
                bytes.copy_from_slice(&user_public_key.key[0..PUBKEY_LEN]);
                Ok(CspPublicKey::Ed25519(ed25519_types::PublicKeyBytes(bytes)))
            }
            AlgorithmId::EcdsaP256 => Ok(CspPublicKey::EcdsaP256(
                ecdsa_secp256r1_types::PublicKeyBytes(user_public_key.key.to_owned()),
            )),
            AlgorithmId::EcdsaSecp256k1 => Ok(CspPublicKey::EcdsaSecp256k1(
                ecdsa_secp256k1_types::PublicKeyBytes(user_public_key.key.to_owned()),
            )),
            AlgorithmId::RsaSha256 => Ok(CspPublicKey::RsaSha256(
                rsa::RsaPublicKey::from_der_spki(&user_public_key.key)?,
            )),
            algorithm => Err(CryptoError::AlgorithmNotSupported {
                algorithm,
                reason: "Could not convert UserPublicKey to CspPublicKey".to_string(),
            }),
        }
    }
}

impl TryFrom<CspSecretKey> for threshold_types::SecretKeyBytes {
    type Error = CspSecretKeyConversionError;
    fn try_from(value: CspSecretKey) -> Result<Self, Self::Error> {
        if let CspSecretKey::ThresBls12_381(key) = value {
            Ok(key)
        } else {
            // TODO (CRP-822): Add the error type to the error message.
            Err(CspSecretKeyConversionError::WrongSecretKeyType {})
        }
    }
}

/// Error while converting secret key
pub enum CspSecretKeyConversionError {
    WrongSecretKeyType,
}

impl TryFrom<CspSignature> for threshold_types::IndividualSignatureBytes {
    type Error = CryptoError;
    fn try_from(value: CspSignature) -> Result<Self, Self::Error> {
        if let CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual(signature)) = value
        {
            Ok(signature)
        } else {
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: value.as_ref().to_owned(),
                internal_error: "Not an individual threshold signature".to_string(),
            })
        }
    }
}

impl TryFrom<CspSignature> for threshold_types::CombinedSignatureBytes {
    type Error = CryptoError;
    fn try_from(value: CspSignature) -> Result<Self, Self::Error> {
        if let CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined(signature)) = value {
            Ok(signature)
        } else {
            Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: value.as_ref().to_owned(),
                internal_error: "Not a combined threshold signature".to_string(),
            })
        }
    }
}

impl TryFrom<CspSecretKey> for EphemeralKeySetBytes {
    type Error = dkg_errors::MalformedSecretKeyError;
    fn try_from(value: CspSecretKey) -> Result<Self, Self::Error> {
        if let CspSecretKey::Secp256k1WithPublicKey(key_set) = value {
            Ok(key_set)
        } else {
            Err(dkg_errors::MalformedSecretKeyError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Could not parse ephemeral key set".to_string(),
            })
        }
    }
}

impl SigConverter {
    pub fn for_target(algorithm: AlgorithmId) -> Self {
        SigConverter {
            target_algorithm: algorithm,
        }
    }
}

impl From<&CspPop> for EncryptionPublicKeyPop {
    fn from(csp_pop: &CspPop) -> Self {
        EncryptionPublicKeyPop(
            serde_cbor::to_vec(csp_pop).expect("Cannot serialize csp encryption public key pop"),
        )
    }
}
