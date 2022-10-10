mod csp_tests {
    use crate::api::CspSigner;
    use crate::api::CspTlsHandshakeSignerProvider;
    use crate::api::{CspKeyGenerator, CspSecretKeyStoreChecker};
    use crate::keygen::tls_cert_hash_as_key_id;
    use crate::public_key_hash_as_key_id;
    use crate::secret_key_store::volatile_store::VolatileSecretKeyStore;
    use crate::vault::test_utils::tls::ed25519_csp_pubkey_from_tls_pubkey_cert;
    use crate::CryptoRng;
    use crate::Csp;
    use crate::CspPublicKey;
    use crate::Rng;
    use ic_crypto_tls_interfaces::TlsPublicKeyCert;
    use ic_types::crypto::AlgorithmId;
    use ic_types_test_utils::ids::node_test_id;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn should_contain_newly_generated_secret_key_from_store() {
        let (csp, public_key) = csp_with_key_pair();
        let key_id = public_key_hash_as_key_id(&public_key);

        let is_contained_in_sks_store = csp
            .sks_contains(&key_id)
            .expect("error looking for secret key");

        assert!(is_contained_in_sks_store);
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_secret_key_from_store() {
        let (csp, public_key) = csp_with_key_pair();
        let key_id = public_key_hash_as_key_id(&public_key);
        let message = "Hello world!".as_bytes();

        let signature = csp
            .sign(AlgorithmId::Ed25519, message, key_id)
            .expect("error signing message");

        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    #[test]
    fn should_contain_newly_generated_tls_secret_key_from_store() {
        let (csp, cert) = csp_with_tls_key_pair();

        let is_contained_in_sks_store = csp
            .sks_contains_tls_key(&cert)
            .expect("error looking for TLS secret key");

        assert!(is_contained_in_sks_store);
    }

    #[test]
    fn should_sign_and_verify_with_newly_generated_tls_secret_key_from_store() {
        let (csp, cert) = csp_with_tls_key_pair();
        let key_id = tls_cert_hash_as_key_id(&cert);
        let message = "Hello world!".as_bytes();

        let signature = csp
            .handshake_signer()
            .tls_sign(message, &key_id)
            .expect("error signing message with TLS private key");

        let public_key = ed25519_csp_pubkey_from_tls_pubkey_cert(&cert);
        let verification = csp.verify(&signature, message, AlgorithmId::Ed25519, public_key);

        assert!(verification.is_ok());
    }

    fn csp_with_key_pair() -> (Csp, CspPublicKey) {
        let csp = Csp::of(csprng(), VolatileSecretKeyStore::new());
        let public_key = csp
            .gen_key_pair(AlgorithmId::Ed25519)
            .expect("error generating public/private key pair");
        (csp, public_key)
    }

    fn csp_with_tls_key_pair() -> (Csp, TlsPublicKeyCert) {
        const NODE_1: u64 = 4241;
        const NOT_AFTER: &str = "25670102030405Z";
        let csp = Csp::of(csprng(), VolatileSecretKeyStore::new());
        let cert = csp
            .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
            .expect("error generating TLS key pair");
        (csp, cert)
    }

    fn csprng() -> impl CryptoRng + Rng + Clone {
        ChaCha20Rng::seed_from_u64(42)
    }
}
