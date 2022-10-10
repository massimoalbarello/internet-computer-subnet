#![allow(clippy::unwrap_used)]

use super::*;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::api::NodePublicKeyData;
use ic_crypto_test_utils::empty_fake_registry;
use ic_interfaces::crypto::KeyManager;
use ic_interfaces_registry::RegistryClient;
use ic_types_test_utils::ids::node_test_id;

#[test]
fn should_have_the_csp_public_keys_that_were_previously_generated() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let csp = csp_for_config(&config, None);
        assert_eq!(node_pks, csp.node_public_keys());
    })
}

#[test]
fn should_generate_all_keys_for_a_node_without_public_keys() {
    CryptoConfig::run_with_temp_config(|config| {
        let csp = csp_for_config(&config, None);
        let first_node_signing_pk = generate_node_signing_keys(&csp);
        // first_node_signing_pk NOT saved.

        let (node_pks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
        ensure_node_keys_are_generated_correctly(&node_pks, &node_id);
        assert_ne!(
            first_node_signing_pk,
            *node_pks.node_signing_pk.as_ref().unwrap()
        );

        let csp = csp_for_config(&config, None);
        assert_eq!(node_pks, csp.node_public_keys());
    })
}

#[test]
fn should_correctly_generate_node_signing_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let nspk = node_pks.node_signing_pk.expect("missing key");
        assert_eq!(nspk.version, 0);
        assert_eq!(nspk.algorithm, AlgorithmIdProto::Ed25519 as i32);
        assert!(!nspk.key_value.is_empty());
        assert!(nspk.proof_data.is_none());
    })
}

#[test]
fn should_correctly_generate_committee_signing_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let cspk = node_pks.committee_signing_pk.expect("missing key");
        assert_eq!(cspk.version, 0);
        assert_eq!(cspk.algorithm, AlgorithmIdProto::MultiBls12381 as i32);
        assert!(!cspk.key_value.is_empty());
        assert!(cspk.proof_data.is_some());
        assert!(!cspk.proof_data.unwrap().is_empty());
    })
}

#[test]
fn should_correctly_generate_dkg_dealing_encryption_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        let ni_dkg_de_pk = node_pks.dkg_dealing_encryption_pk.expect("missing key");
        assert_eq!(ni_dkg_de_pk.version, 0);
        assert_eq!(
            ni_dkg_de_pk.algorithm,
            AlgorithmIdProto::Groth20Bls12381 as i32
        );
        assert!(!ni_dkg_de_pk.key_value.is_empty());
        assert!(ni_dkg_de_pk.proof_data.is_some());
        assert!(!ni_dkg_de_pk.proof_data.unwrap().is_empty());
    })
}

#[test]
fn should_correctly_generate_tls_certificate() {
    CryptoConfig::run_with_temp_config(|config| {
        let (node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
        assert!(node_pks.tls_certificate.is_some());
        assert!(!node_pks.tls_certificate.unwrap().certificate_der.is_empty());
    })
}

#[test]
fn should_correctly_generate_idkg_dealing_encryption_key() {
    CryptoConfig::run_with_temp_config(|config| {
        let mut csp = csp_for_config(&config, None);
        let public_key = generate_idkg_dealing_encryption_keys(&mut csp);
        assert_eq!(public_key.version, 0);
        assert_eq!(public_key.algorithm, AlgorithmIdProto::MegaSecp256k1 as i32);
        assert!(!public_key.key_value.is_empty());
        assert!(public_key.proof_data.is_none());
    })
}

#[test]
fn should_correctly_generate_idkg_keys_if_other_keys_already_present_with_version_0_and_not_regenerate_others(
) {
    CryptoConfig::run_with_temp_config(|config| {
        let (npks_before, node_id_1) = {
            let (npks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
            assert!(all_node_keys_are_present(&npks));
            assert_eq!(npks.version, 1);
            let npks_version_0_without_idkg_dealing_encryption_key = NodePublicKeys {
                version: 0,
                idkg_dealing_encryption_pk: None,
                ..npks
            };
            store_public_keys(
                &config.crypto_root,
                &npks_version_0_without_idkg_dealing_encryption_key,
            );
            assert_eq!(
                read_public_keys(&config.crypto_root).unwrap(),
                npks_version_0_without_idkg_dealing_encryption_key
            );
            (npks_version_0_without_idkg_dealing_encryption_key, node_id)
        };

        let (npks_after, node_id_2) = get_node_keys_or_generate_if_missing(&config, None);
        // Ensure keys have version 1 and are correctly stored
        assert_eq!(npks_after.version, 1);
        assert!(all_node_keys_are_present(&npks_after));
        assert_eq!(read_public_keys(&config.crypto_root).unwrap(), npks_after);

        // Ensure I-DKG key is present and generated correctly
        assert!(npks_after.idkg_dealing_encryption_pk.is_some());
        if let Some(idkg_pk) = npks_after.idkg_dealing_encryption_pk {
            assert_eq!(idkg_pk.version, 0);
            assert_eq!(idkg_pk.algorithm, AlgorithmIdProto::MegaSecp256k1 as i32);
            assert!(!idkg_pk.key_value.is_empty());
            assert!(idkg_pk.proof_data.is_none());
        }

        // Ensure node ID and pre-existing key material is unchanged
        assert_eq!(node_id_1, node_id_2);
        assert_eq!(npks_before.node_signing_pk, npks_after.node_signing_pk);
        assert_eq!(
            npks_before.committee_signing_pk,
            npks_after.committee_signing_pk
        );
        assert_eq!(
            npks_before.dkg_dealing_encryption_pk,
            npks_after.dkg_dealing_encryption_pk
        );
        assert_eq!(npks_before.tls_certificate, npks_after.tls_certificate);
    })
}

#[test]
fn should_correctly_generate_idkg_keys_if_other_keys_already_present_with_version_1_and_not_regenerate_others(
) {
    CryptoConfig::run_with_temp_config(|config| {
        let (npks_before, node_id_1) = {
            let (npks, node_id) = get_node_keys_or_generate_if_missing(&config, None);
            assert!(all_node_keys_are_present(&npks));
            assert_eq!(npks.version, 1);
            let npks_version_1_without_idkg_dealing_encryption_key = NodePublicKeys {
                idkg_dealing_encryption_pk: None,
                ..npks
            };
            store_public_keys(
                &config.crypto_root,
                &npks_version_1_without_idkg_dealing_encryption_key,
            );
            assert_eq!(
                read_public_keys(&config.crypto_root).unwrap(),
                npks_version_1_without_idkg_dealing_encryption_key
            );
            (npks_version_1_without_idkg_dealing_encryption_key, node_id)
        };

        let (npks_after, node_id_2) = get_node_keys_or_generate_if_missing(&config, None);
        // Ensure keys have version 1 and are correctly stored
        assert_eq!(npks_after.version, 1);
        assert!(all_node_keys_are_present(&npks_after));
        assert_eq!(read_public_keys(&config.crypto_root).unwrap(), npks_after);

        // Ensure I-DKG key is present and generated correctly
        assert!(npks_after.idkg_dealing_encryption_pk.is_some());
        if let Some(idkg_pk) = npks_after.idkg_dealing_encryption_pk {
            assert_eq!(idkg_pk.version, 0);
            assert_eq!(idkg_pk.algorithm, AlgorithmIdProto::MegaSecp256k1 as i32);
            assert!(!idkg_pk.key_value.is_empty());
            assert!(idkg_pk.proof_data.is_none());
        }

        // Ensure node ID and pre-existing key material is unchanged
        assert_eq!(node_id_1, node_id_2);
        assert_eq!(npks_before.node_signing_pk, npks_after.node_signing_pk);
        assert_eq!(
            npks_before.committee_signing_pk,
            npks_after.committee_signing_pk
        );
        assert_eq!(
            npks_before.dkg_dealing_encryption_pk,
            npks_after.dkg_dealing_encryption_pk
        );
        assert_eq!(npks_before.tls_certificate, npks_after.tls_certificate);
    })
}

#[test]
#[should_panic(expected = "inconsistent key material")]
fn should_panic_if_node_has_inconsistent_keys() {
    let (temp_crypto, _node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_node_signing_key(),
        );
        node_keys2.node_signing_pk
    };

    // Store different_node_signing_pk in temp_crypto's crypto_root.
    store_public_keys(
        temp_crypto.temp_dir_path(),
        &NodePublicKeys {
            node_signing_pk: different_node_signing_pk,
            ..Default::default()
        },
    );
    let config = CryptoConfig::new(temp_crypto.temp_dir_path().to_path_buf());
    let (_node_pks, _node_id) = get_node_keys_or_generate_if_missing(&config, None);
}

#[test]
fn check_keys_locally_returns_none_if_no_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let result = check_keys_locally(&config, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    })
}

#[test]
fn check_keys_locally_returns_none_if_no_public_keys_are_present() {
    CryptoConfig::run_with_temp_config(|config| {
        let csp = csp_for_config(&config, None);
        let _node_signing_pk = generate_node_signing_keys(&csp);
        // _node_signing_pk NOT saved.
        let result = check_keys_locally(&config, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    })
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_node_signing_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::only_node_signing_key(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_node_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_node_signing_key(),
        );
        node_keys2.node_signing_pk
    };
    assert_ne!(node_keys.node_signing_pk, different_node_signing_pk);
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            node_signing_pk: different_node_signing_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::Ed25519
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_committee_signing_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_committee_signing_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_committee_signing_key(),
        );
        node_keys2.committee_signing_pk
    };
    assert_ne!(
        node_keys.committee_signing_pk,
        different_committee_signing_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            committee_signing_pk: different_committee_signing_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::MultiBls12_381
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_dkg_dealing_encryption_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_dkg_dealing_enc_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_dkg_dealing_encryption_key(),
        );
        node_keys2.dkg_dealing_encryption_pk
    };
    assert_ne!(
        node_keys.dkg_dealing_encryption_pk,
        different_dkg_dealing_enc_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            dkg_dealing_encryption_pk: different_dkg_dealing_enc_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::Groth20_Bls12_381
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_idkg_dealing_encryption_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_idkg_dealing_enc_pk = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_idkg_dealing_encryption_key(),
        );
        node_keys2.idkg_dealing_encryption_pk
    };
    assert_ne!(
        node_keys.idkg_dealing_encryption_pk,
        different_idkg_dealing_enc_pk
    );
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            idkg_dealing_encryption_pk: different_idkg_dealing_enc_pk,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::SecretKeyNotFound { algorithm, .. })
        if algorithm == AlgorithmId::MegaSecp256k1
    ));
}

#[test]
fn should_fail_check_keys_locally_if_no_matching_tls_secret_key_is_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    let different_tls_cert = {
        let (_temp_crypto2, node_keys2) = crypto_with_node_keys_generation(
            empty_fake_registry(),
            node_test_id(2),
            NodeKeysToGenerate::only_tls_key_and_cert(),
        );
        node_keys2.tls_certificate
    };
    assert_ne!(node_keys.tls_certificate, different_tls_cert);
    store_public_keys(
        crypto_root.as_path(),
        &NodePublicKeys {
            tls_certificate: different_tls_cert,
            ..node_keys
        },
    );

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(
        result,
        Err(CryptoError::TlsSecretKeyNotFound { .. })
    ));
}

#[test]
fn should_succeed_check_keys_locally_if_all_keys_are_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all(),
    );
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    store_public_keys(crypto_root.as_path(), &node_keys);

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(result, Ok(Some(_))));
}

#[test]
fn should_succeed_check_keys_locally_if_all_keys_except_idkg_dealing_enc_key_are_present() {
    let (temp_crypto, node_keys) = crypto_with_node_keys_generation(
        empty_fake_registry(),
        node_test_id(1),
        NodeKeysToGenerate::all_except_idkg_dealing_encryption_key(),
    );
    assert!(node_keys.idkg_dealing_encryption_pk.is_none());
    let crypto_root = temp_crypto.temp_dir_path().to_path_buf();
    store_public_keys(crypto_root.as_path(), &node_keys);

    let result = check_keys_locally(&CryptoConfig::new(crypto_root), None);

    assert!(matches!(result, Ok(Some(_))));
}

mod tls {
    use super::super::generate_tls_keys;
    use crate::utils::local_csp_in_temp_dir;
    use ic_types_test_utils::ids::node_test_id;
    use openssl::x509::X509VerifyResult;
    use openssl::{asn1::Asn1Time, nid::Nid, x509::X509NameEntryRef, x509::X509};

    const NODE_ID: u64 = 123;

    #[test]
    fn should_return_self_signed_certificate() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();
        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let public_key = x509_cert.public_key().unwrap();
        assert_eq!(x509_cert.verify(&public_key).ok(), Some(true));
        assert_eq!(x509_cert.issued(x509_cert), X509VerifyResult::OK);
    }

    #[test]
    fn should_not_set_subject_alt_name() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();
        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let subject_alt_names = x509_cert.subject_alt_names();
        assert!(subject_alt_names.is_none());
    }

    #[test]
    fn should_set_cert_issuer_and_subject_cn_as_node_id() {
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();

        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let x509_cert = cert.as_x509();
        let issuer_cn = issuer_cn(x509_cert);
        let subject_cn = subject_cn(x509_cert);
        let expected_cn = node_test_id(NODE_ID).get().to_string();
        assert_eq!(expected_cn.as_bytes(), issuer_cn.data().as_slice());
        assert_eq!(expected_cn.as_bytes(), subject_cn.data().as_slice());
    }

    #[test]
    fn should_set_cert_not_after_correctly() {
        const RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE: &str = "99991231235959Z";
        let (mut csp, _temp_dir) = local_csp_in_temp_dir();

        let cert = generate_tls_keys(&mut csp, node_test_id(NODE_ID));

        let expected_not_after =
            Asn1Time::from_str_x509(RFC5280_NO_WELL_DEFINED_CERTIFICATE_EXPIRATION_DATE).unwrap();
        assert!(cert.as_x509().not_after() == expected_not_after);
    }

    fn subject_cn(x509_cert: &X509) -> &X509NameEntryRef {
        x509_cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
    }

    fn issuer_cn(x509_cert: &X509) -> &X509NameEntryRef {
        x509_cert
            .issuer_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
    }
}

fn ensure_node_keys_are_generated_correctly(node_pks: &NodePublicKeys, node_id: &NodeId) {
    assert!(all_node_keys_are_present(node_pks));
    assert_eq!(node_pks.version, 1);

    let node_signing_pk = node_pks
        .node_signing_pk
        .as_ref()
        .expect("Missing node signing public key");
    let derived_node_id = derive_node_id(node_signing_pk);
    assert_eq!(*node_id, derived_node_id);
}

fn all_node_keys_are_present(node_pks: &NodePublicKeys) -> bool {
    node_pks.node_signing_pk.is_some()
        && node_pks.committee_signing_pk.is_some()
        && node_pks.tls_certificate.is_some()
        && node_pks.dkg_dealing_encryption_pk.is_some()
        && node_pks.idkg_dealing_encryption_pk.is_some()
}

fn store_public_keys(crypto_root: &Path, node_pks: &NodePublicKeys) {
    public_key_store::store_node_public_keys(crypto_root, node_pks).unwrap();
}

fn crypto_with_node_keys_generation(
    registry_client: Arc<dyn RegistryClient>,
    node_id: NodeId,
    selector: NodeKeysToGenerate,
) -> (TempCryptoComponent, NodePublicKeys) {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(registry_client)
        .with_node_id(node_id)
        .with_keys(selector)
        .build();
    let node_public_keys = temp_crypto.node_public_keys();
    (temp_crypto, node_public_keys)
}
