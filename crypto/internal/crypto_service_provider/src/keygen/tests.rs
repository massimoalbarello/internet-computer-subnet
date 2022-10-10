#![allow(clippy::unwrap_used)]
use super::*;
use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_test_vectors::unhex::{hex_to_32_bytes, hex_to_byte_vec};
use ic_types_test_utils::ids::node_test_id;
use openssl::x509::X509NameEntries;
use openssl::{asn1::Asn1Time, bn::BigNum, nid::Nid, x509::X509};
use rand::CryptoRng;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn should_correctly_generate_ed25519_keys() {
    let csprng = csprng_seeded_with(42);
    let csp = Csp::of(csprng, volatile_key_store());

    let pk = csp.gen_key_pair(AlgorithmId::Ed25519).unwrap();
    let key_id = public_key_hash_as_key_id(&pk);

    assert_eq!(
        key_id,
        KeyId::from(hex_to_32_bytes(
            "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
        )),
    );
    assert_eq!(
        pk,
        CspPublicKey::ed25519_from_hex(
            "78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"
        )
    );
}

#[test]
/// If this test fails, old key IDs in the SKS will no longer work!
fn should_correctly_convert_tls_cert_hash_as_key_id() {
    // openssl-generated example X509 cert.
    let cert_der = hex_to_byte_vec(
        "308201423081f5a00302010202147dfa\
         b83de61da8c8aa957cbc6ad9645f2bbc\
         c9f8300506032b657030173115301306\
         035504030c0c4446494e495459205465\
         7374301e170d32313036303331373337\
         35305a170d3231303730333137333735\
         305a30173115301306035504030c0c44\
         46494e4954592054657374302a300506\
         032b657003210026c5e95c453549621b\
         2dc6475e0dde204caa3e4f326f4728fd\
         0458e7771ac03ca3533051301d060355\
         1d0e0416041484696f2370163c1c489c\
         095dfea6574a3fa88ad5301f0603551d\
         2304183016801484696f2370163c1c48\
         9c095dfea6574a3fa88ad5300f060355\
         1d130101ff040530030101ff30050603\
         2b65700341009b0e731565bcfaedb6c7\
         0805fa75066ff931b8bc6993c10bf020\
         2c14b96ab5abd0704f163cb0a6b57621\
         2b2eb8ddf74ab60d5cdc59f906acc8a1\
         24678c290e06",
    );
    let cert = TlsPublicKeyCert::new_from_der(cert_der)
        .expect("failed to build TlsPublicKeyCert from DER");

    let key_id = tls_cert_hash_as_key_id(&cert);

    // We expect the following hard coded key id:
    let expected_key_id =
        hex_to_32_bytes("bc1f70570a2aaa0904069e1a77b710c729ac1bf026a02f14ad8613c3627b211a");
    assert_eq!(key_id, KeyId(expected_key_id));
}

fn csprng_seeded_with(seed: u64) -> impl CryptoRng + Rng + Clone {
    ChaCha20Rng::seed_from_u64(seed)
}

fn volatile_key_store() -> VolatileSecretKeyStore {
    VolatileSecretKeyStore::new()
}

mod multi {
    use super::*;
    use ic_crypto_internal_multi_sig_bls12381::types::{PopBytes, PublicKeyBytes};
    use ic_crypto_internal_test_vectors::unhex::{hex_to_48_bytes, hex_to_96_bytes};

    struct TestVector {
        seed: u64,
        key_id: KeyId,
        public_key: CspPublicKey,
        proof_of_possession: CspPop,
    }

    fn test_vector_42() -> TestVector {
        TestVector {
            seed: 42,
            key_id: KeyId::from(hex_to_32_bytes(
                "6ddef5dfbbd4b641a7cc838ea5d2018c892dd6ef21d641a93f9d3b73b95c6258",
            )),
            public_key: CspPublicKey::MultiBls12_381(PublicKeyBytes(hex_to_96_bytes(
                "b5077d187db1ff824d246bc7c311f909047e20375dc836087da1d7e5c3add0e8fc838af6aaa7373b41824c9bd080f47c0a50e3cdf06bf1cb4061a6cc6ab1802acce096906cece92e7487a29e89a187b618e6af1292515202640795f3359161c2",
            ))),
            proof_of_possession: CspPop::MultiBls12_381(PopBytes(hex_to_48_bytes(
                "8c3a46485252433f478d733275ae3d259f6ced963cf496974ea1dc95e6ca3aee588c4a2e12de34f46e7ef0adffe664d7",
            ))),
        }
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let public_key = csp.gen_key_pair(AlgorithmId::MultiBls12_381).unwrap();
        let key_id = public_key_hash_as_key_id(&public_key);

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
    }

    /// This test checks that the functionality is consistent; the values are
    /// not "correct" but they must never change.
    #[test]
    fn key_generation_with_pop_is_stable() {
        let test_vector = test_vector_42();
        let csprng = csprng_seeded_with(test_vector.seed);
        let csp = Csp::of(csprng, volatile_key_store());
        let (public_key, pop) = csp
            .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
            .expect("Failed to generate key pair with PoP");
        let key_id = public_key_hash_as_key_id(&public_key);

        assert_eq!(key_id, test_vector.key_id);
        assert_eq!(public_key, test_vector.public_key);
        assert_eq!(pop, test_vector.proof_of_possession);
    }
}

mod tls {
    use super::*;
    use crate::secret_key_store::test_utils::MockSecretKeyStore;
    use crate::secret_key_store::SecretKeyStoreError;
    use openssl::x509::X509VerifyResult;
    use std::collections::BTreeSet;

    const NODE_1: u64 = 4241;
    const FIXED_SEED: u64 = 42;
    const NOT_AFTER: &str = "25670102030405Z";

    #[test]
    #[should_panic(expected = "has already been inserted")]
    fn should_panic_if_secret_key_insertion_yields_duplicate_error() {
        let mut sks_returning_error_on_insert = MockSecretKeyStore::new();
        sks_returning_error_on_insert
            .expect_insert()
            .times(1)
            .return_const(Err(SecretKeyStoreError::DuplicateKeyId(KeyId::from(
                [42; 32],
            ))));

        let csp = Csp::of(rng(), sks_returning_error_on_insert);

        let _ = csp.gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER);
    }

    #[test]
    fn should_return_der_encoded_self_signed_certificate() {
        let csp = Csp::of(rng(), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_set_cert_subject_cn_as_node_id() {
        let csp = Csp::of(rng(), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let x509_cert = cert.as_x509();
        assert_eq!(cn_entries(x509_cert).count(), 1);
        let subject_cn = cn_entries(x509_cert).next().unwrap();
        let expected_subject_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_subject_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_use_stable_node_id_string_representation_as_subject_cn() {
        let csp = Csp::of(rng(), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let subject_cn = cn_entries(cert.as_x509()).next().unwrap();
        assert_eq!(b"w43gn-nurca-aaaaa-aaaap-2ai", subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_issuer_cn_as_node_id() {
        let csp = Csp::of(rng(), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let issuer_cn = cert
            .as_x509()
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        let expected_issuer_cn = node_test_id(NODE_1).get().to_string();
        assert_eq!(expected_issuer_cn.as_bytes(), issuer_cn.data().as_slice());
    }

    #[test]
    fn should_not_set_cert_subject_alt_name() {
        let csp = Csp::of(rng(), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let subject_alt_names = cert.as_x509().subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_random_cert_serial_number() {
        let csp = Csp::of(csprng_seeded_with(FIXED_SEED), volatile_key_store());

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS certificate");

        let cert_serial = cert.as_x509().serial_number().to_bn().unwrap();
        let expected_randomness = csprng_seeded_with(FIXED_SEED).gen::<[u8; 19]>();
        let expected_serial = BigNum::from_slice(&expected_randomness).unwrap();
        assert_eq!(expected_serial, cert_serial);
    }

    #[test]
    fn should_set_different_serial_numbers_for_multiple_certs() {
        let csp = Csp::of(rng(), volatile_key_store());

        const SAMPLE_SIZE: usize = 20;
        let mut serial_samples = BTreeSet::new();
        for _i in 0..SAMPLE_SIZE {
            let cert = csp
                .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
                .expect("error generating TLS certificate");
            serial_samples.insert(serial_number(&cert));
        }
        assert_eq!(serial_samples.len(), SAMPLE_SIZE);
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        let csp = Csp::of(rng(), volatile_key_store());
        let not_after = NOT_AFTER;

        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), not_after)
            .expect("error generating TLS certificate");

        assert!(cert.as_x509().not_after() == Asn1Time::from_str_x509(not_after).unwrap());
    }

    #[test]
    fn should_panic_on_invalid_not_after_date() {
        let csp = Csp::of(rng(), volatile_key_store());
        let invalid_not_after = "invalid_not_after_date";

        let result = csp.gen_tls_key_pair(node_test_id(NODE_1), invalid_not_after);
        assert!(
            matches!(result, Err(CryptoError::InvalidNotAfterDate { message, not_after })
                if message.eq("invalid X.509 certificate expiration date (not_after)") && not_after.eq(invalid_not_after)
            )
        );
    }

    #[test]
    fn should_panic_if_not_after_date_is_in_the_past() {
        let csp = Csp::of(rng(), volatile_key_store());
        let date_in_the_past = "20211004235959Z";

        let result = csp.gen_tls_key_pair(node_test_id(NODE_1), date_in_the_past);
        assert!(
            matches!(result, Err(CryptoError::InvalidNotAfterDate { message, not_after })
                if message.eq("'not after' date must not be in the past") && not_after.eq(date_in_the_past)
            )
        );
    }

    fn rng() -> impl CryptoRng + Rng + Clone {
        csprng_seeded_with(42)
    }

    fn cn_entries(x509_cert: &X509) -> X509NameEntries {
        x509_cert.subject_name().entries_by_nid(Nid::COMMONNAME)
    }

    fn serial_number(cert: &TlsPublicKeyCert) -> BigNum {
        cert.as_x509().serial_number().to_bn().unwrap()
    }
}

#[cfg(test)]
mod key_id_generation_stability_tests {
    use crate::key_id::KeyId;
    use crate::keygen::commitment_key_id;
    use crate::keygen::mega_key_id;
    use crate::keygen::tls_cert_hash_as_key_id;
    use crate::public_key_hash_as_key_id;
    use crate::CspPublicKey;
    use ic_crypto_internal_test_vectors::ed25519::TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_PK;
    use ic_crypto_internal_test_vectors::ed25519::TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_PK;
    use ic_crypto_internal_test_vectors::ed25519::TESTVEC_RFC8032_ED25519_SHA_ABC_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_1_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_2_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_3_PK;
    use ic_crypto_internal_test_vectors::multi_bls12_381::TESTVEC_MULTI_BLS12_381_4_PK;
    use ic_crypto_internal_threshold_sig_ecdsa::PedersenCommitment;
    use ic_crypto_internal_threshold_sig_ecdsa::{
        EccCurveType, EccPoint, MEGaPublicKey, PolynomialCommitment, SimpleCommitment,
    };
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use openssl::x509::X509;
    use std::fmt::Debug;

    #[derive(Debug)]
    struct ParameterizedTest<U, V> {
        input: U,
        expected: V,
    }

    #[test]
    fn should_public_key_hash_as_key_id_be_stable() {
        let tests = vec![
            ParameterizedTest {
                input: CspPublicKey::ed25519_from_hex(TESTVEC_RFC8032_ED25519_SHA_ABC_PK),
                expected: "d9564f1e7ab210c9f0c95d4627d5266485b4a7724048a36170c8ff5ac2915a48",
            },
            ParameterizedTest {
                input: CspPublicKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_1_PK),
                expected: "657b58570a2f72f6f24f9d574d766a57d323cbff06914ff70b8c54a0be60afc4",
            },
            ParameterizedTest {
                input: CspPublicKey::ed25519_from_hex(TESTVEC_MESSAGE_LEN_256_BIT_STABILITY_2_PK),
                expected: "1566296d90371b5273ec084fbdfeb80d06036bb9556657dacff522670ada424e",
            },
            ParameterizedTest {
                input: CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_1_PK),
                expected: "bf7002780d49b0d397873f1638bbc7adb9f0b44071561a040b39291b92325875",
            },
            ParameterizedTest {
                input: CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_2_PK),
                expected: "db832fa83c8b613abe4706dfde8f6cf39cba706c37223ac617666b869bf00405",
            },
            ParameterizedTest {
                input: CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_3_PK),
                expected: "7b96cd3c54b615ae95d4862bfafbb17c5771ff3949b5eacb8fab53ae363b68e3",
            },
            ParameterizedTest {
                input: CspPublicKey::multi_bls12381_from_hex(TESTVEC_MULTI_BLS12_381_4_PK),
                expected: "e1299603ca276e7164d25be3596f98c6139202959b6a83195acf0c5121d57742",
            },
        ];

        for test in &tests {
            assert_eq!(
                public_key_hash_as_key_id(&test.input),
                KeyId::from(hex_to_bytes(&test.expected)),
                "Parameterized test {:?} failed",
                &test
            );
        }
    }

    #[test]
    fn should_mega_key_id_be_stable() {
        let tests = vec![
            ParameterizedTest {
                input: MEGaPublicKey::new(EccPoint::identity(EccCurveType::K256)),
                expected: "ea1004285ebbadc58afc93ca583973c793e1ee5c9cefa7d0165491f19937c1ed",
            },
            ParameterizedTest {
                input: MEGaPublicKey::new(
                    EccPoint::generator_g(EccCurveType::K256).expect("error retrieving generator"),
                ),
                expected: "4aeda75e42b4ca12c3d278a4684849bccbfd3ed6861d16fbee6c2585e7560039",
            },
            ParameterizedTest {
                input: MEGaPublicKey::new(
                    EccPoint::generator_h(EccCurveType::K256).expect("error retrieving generator"),
                ),
                expected: "502da182fa4451163418bb07073182ca280aa4fb1f652b70f5b3b8f1642579cb",
            },
        ];
        for test in &tests {
            assert_eq!(
                mega_key_id(&test.input),
                KeyId::from(hex_to_bytes(&test.expected)),
                "Parameterized test {:?} failed",
                &test
            );
        }
    }

    #[test]
    fn should_commitment_key_id_be_stable() {
        let generator_g_k256 =
            EccPoint::generator_g(EccCurveType::K256).expect("error retrieving generator");
        let generator_h_k256 =
            EccPoint::generator_h(EccCurveType::K256).expect("error retrieving generator");

        let generator_g_p256 =
            EccPoint::generator_g(EccCurveType::P256).expect("error retrieving generator");
        let generator_h_p256 =
            EccPoint::generator_h(EccCurveType::P256).expect("error retrieving generator");
        let tests = vec![
            ParameterizedTest {
                input: PolynomialCommitment::Simple(SimpleCommitment {
                    points: vec![generator_g_k256.clone(), generator_h_k256.clone()],
                }),
                expected: "317266bb4c9a48e402c80df3908872d78514e20ed277c50e32608b1a0b4b8803",
            },
            ParameterizedTest {
                input: PolynomialCommitment::Simple(SimpleCommitment {
                    points: vec![generator_g_p256.clone(), generator_h_p256.clone()],
                }),
                expected: "c8be99e090993026ff60d32f4424f436f3051020cec9a638a47a7db9619e679f",
            },
            ParameterizedTest {
                input: PolynomialCommitment::Pedersen(PedersenCommitment {
                    points: vec![generator_g_k256, generator_h_k256],
                }),
                expected: "e490f204848d40835434944b5a5ee4c9d2ae2c7dc8ea4af8bf66f790f3ee87a2",
            },
            ParameterizedTest {
                input: PolynomialCommitment::Pedersen(PedersenCommitment {
                    points: vec![generator_g_p256, generator_h_p256],
                }),
                expected: "a1211fbc604a231eccd0879b019aea8f1a055ace0d79fd08a78457bef1c01ef8",
            },
        ];

        for test in &tests {
            assert_eq!(
                commitment_key_id(&test.input),
                KeyId::from(hex_to_bytes(&test.expected)),
                "Parameterized test {:?} failed",
                &test
            );
        }
    }

    #[test]
    fn should_tls_cert_hash_as_key_id_be_stable() {
        let docs_rs_cert = r#"-----BEGIN CERTIFICATE-----
MIIFxjCCBK6gAwIBAgIQDF7pmq7PPvZyjj98sQshDzANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRUwEwYDVQQLEwxTZXJ2ZXIg
Q0EgMUIxDzANBgNVBAMTBkFtYXpvbjAeFw0yMjAxMDYwMDAwMDBaFw0yMzAyMDQy
MzU5NTlaMBIxEDAOBgNVBAMTB2RvY3MucnMwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCW2k7u1nH0SK7/cUXUQi8/6wCsb4/4AYaGviyUuc8AMQ/7b/d3
ZcC9tcB4a7D3PjGF1lqsCxA0PqSa/GW3bhB9U2lwpNsFd5gQMDbsbZ+fNHF8aI+Y
HgAJ40XPLV07VMhegSyNYAZWDu4lN9/XPSwKbQ+nYzVp5DBpkC8IuDnUcoCgAxKF
l5+ZwZ/PS9Fvix9hjBA5KmmFDXODM4ivHEmZ584yq4NP6RkfkjeTTGhXvTmJ79LV
4xWM7pWPlCPfENadQSW1J0Gs3E5c7s9TUXFq5d9z11Kssy2RmdLeq+z55sNdx5s/
7wrs1i7pzLN6sc6BCxMLBxJ510g/DrZFwfSbAgMBAAGjggLiMIIC3jAfBgNVHSME
GDAWgBRZpGYGUqB7lZI8o5QHJ5Z0W/k90DAdBgNVHQ4EFgQUQKgdLtwe5AMsKDN5
S5kz0QI5ibcwEgYDVR0RBAswCYIHZG9jcy5yczAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMD0GA1UdHwQ2MDQwMqAwoC6GLGh0
dHA6Ly9jcmwuc2NhMWIuYW1hem9udHJ1c3QuY29tL3NjYTFiLTEuY3JsMBMGA1Ud
IAQMMAowCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggrBgEFBQcwAYYhaHR0
cDovL29jc3Auc2NhMWIuYW1hem9udHJ1c3QuY29tMDYGCCsGAQUFBzAChipodHRw
Oi8vY3J0LnNjYTFiLmFtYXpvbnRydXN0LmNvbS9zY2ExYi5jcnQwDAYDVR0TAQH/
BAIwADCCAX4GCisGAQQB1nkCBAIEggFuBIIBagFoAHcA6D7Q2j71BjUy51covIlr
yQPTy9ERa+zraeF3fW0GvW4AAAF+LUyddwAABAMASDBGAiEAs6bwaF8J8ykU2OqR
m8GwkPGNtA6JIe7yz9pTIu30yjYCIQDRMU6Ae9H2/zXkItJ538iPvsqDX2trKtlO
OgBXPAySugB2ADXPGRu/sWxXvw+tTG1Cy7u2JyAmUeo/4SrvqAPDO9ZMAAABfi1M
nXQAAAQDAEcwRQIhAJHOl+EyCqMRSplGDQVobeSXizm0hlAOyR6Ba1v/ntyzAiAC
/4EW4h/cL6aWABaFnyOOSCHT8NydEyBzk/Y5+w9tpgB1ALNzdwfhhFD4Y4bWBanc
EQlKeS2xZwwLh9zwAw55NqWaAAABfi1MnasAAAQDAEYwRAIgfXZYrSV4w8S5Kwim
+clHZLh8nMwdU9d3G47qHxI1sJcCIH+GHWe32JsqKi0dwEjiQ7/LhAMfznD47bcF
i/ZXNoBBMA0GCSqGSIb3DQEBCwUAA4IBAQBnamHdviwVXKfuLpmvV3FOqUPwUxoo
65v3T0+0AasxSIruWv0JLftB7anCVS/phchB6ZWOVrvv1gOfWQ7p7mTvx3AMQHHi
mo+Gw/VbrZU8zdkEE3iNhSHYg5szS/nwZYiYcLnHI4PlZV26op7Fu/ufLPOrcm42
44UZIihaWJX9zDLi/guVmxBgbVTvGMJdq4FXuztFMApaj9JJ2Gh0zvbBtBpij0Eu
t7Ica9iKR8XXVy+W5eyW52YYPbGzXZ0FgxPcOMk3Tm2qx/zJJ7pkN+rJeIEgQHEj
2nMxM1gYvf7AKqhkVEejCTS4APko/O87gdXnc4uPV0s+YZk3YLXd95t/
-----END CERTIFICATE-----"#;

        let tests = vec![ParameterizedTest {
            input: tls_public_key_cert_from_pem(docs_rs_cert),
            expected: "589e6e2741aef52ae6dd57cd2101d3f1537bff00ccc4a82f340db7a94a232386",
        }];

        for test in &tests {
            assert_eq!(
                tls_cert_hash_as_key_id(&test.input),
                KeyId::from(hex_to_bytes(&test.expected)),
                "Parameterized test {:?} failed",
                &test
            );
        }
    }

    fn tls_public_key_cert_from_pem(pem_cert: &str) -> TlsPublicKeyCert {
        TlsPublicKeyCert::new_from_x509(
            X509::from_pem(pem_cert.as_bytes()).expect("error parsing X509"),
        )
        .expect("error parsing certificate")
    }

    fn hex_to_bytes<T: AsRef<[u8]>, const N: usize>(data: T) -> [u8; N] {
        hex::decode(data)
            .expect("error decoding hex")
            .try_into()
            .expect("wrong size of array")
    }
}
