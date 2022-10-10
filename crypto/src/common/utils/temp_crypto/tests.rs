#![allow(clippy::unwrap_used)]

use super::*;

use ic_crypto_test_utils::empty_fake_registry;
use ic_types_test_utils::ids::node_test_id;

const NODE_ID: u64 = 42;

#[test]
fn should_delete_tempdir_when_temp_crypto_goes_out_of_scope() {
    let path = {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(empty_fake_registry())
            .with_node_id(node_test_id(NODE_ID))
            .build();
        temp_crypto.temp_dir.path().to_path_buf()
    };
    assert!(!path.exists());
}

#[test]
fn should_create_tempdir_as_directory() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    assert!(temp_crypto.temp_dir.path().is_dir());
}

#[test]
fn should_create_with_tempdir_that_exists() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    assert!(temp_crypto.temp_dir.path().exists());
}

#[test]
fn should_set_correct_tempdir_permissions() {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(empty_fake_registry())
        .with_node_id(node_test_id(NODE_ID))
        .build();
    let result = CryptoConfig::check_dir_has_required_permissions(temp_crypto.temp_dir.path());
    assert!(result.is_ok(), "{:?}", result);
}
