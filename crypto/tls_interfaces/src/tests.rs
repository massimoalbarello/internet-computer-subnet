#![allow(clippy::unwrap_used)]

mod tls_public_key_cert {
    use ic_crypto_test_utils::tls::x509_certificates::generate_ed25519_cert;

    use crate::{TlsPublicKeyCert, TlsPublicKeyCertCreationError};

    #[test]
    fn should_create_certificate_from_valid_x509() {
        let cert_x509 = generate_ed25519_cert().1;

        let cert = TlsPublicKeyCert::new_from_x509(cert_x509.clone()).unwrap();

        assert_eq!(
            cert_x509.to_der().expect("failed to convert X509 to DER"),
            *cert.as_der()
        );
    }

    #[test]
    fn should_create_certificate_from_valid_der() {
        let cert_der = generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER");

        let cert = TlsPublicKeyCert::new_from_der(cert_der.clone()).unwrap();

        assert_eq!(cert_der, *cert.as_der());
    }

    #[test]
    fn should_create_equal_from_der_and_x509() {
        let cert_x509 = generate_ed25519_cert().1;
        let cert_der = cert_x509.to_der().expect("failed to convert X509 to DER");

        let cert1 = TlsPublicKeyCert::new_from_x509(cert_x509).unwrap();

        let cert2 = TlsPublicKeyCert::new_from_der(cert_der).unwrap();

        assert_eq!(cert1, cert2);
    }

    #[test]
    fn should_return_proto_with_correct_der() {
        let cert_der = generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER");

        let cert = TlsPublicKeyCert::new_from_der(cert_der.clone()).unwrap();

        assert_eq!(cert_der, cert.to_proto().certificate_der);
    }

    #[test]
    fn should_equal_with_same_der() {
        let cert_der = generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER");

        let cert1 = TlsPublicKeyCert::new_from_der(cert_der.clone()).unwrap();
        let cert2 = TlsPublicKeyCert::new_from_der(cert_der).unwrap();

        assert_eq!(cert1, cert2);
        assert_eq!(cert1.as_der(), cert2.as_der());
    }

    #[test]
    fn should_not_equal_to_other() {
        let cert_der1 = generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER");

        let cert1 = TlsPublicKeyCert::new_from_der(cert_der1).unwrap();

        let cert_der2 = generate_ed25519_cert()
            .1
            .to_der()
            .expect("Failed to convert X509 to DER");

        let cert2 = TlsPublicKeyCert::new_from_der(cert_der2).unwrap();

        assert_ne!(cert1, cert2);
    }

    #[test]
    fn should_return_error_if_der_empty() {
        let empty_der = Vec::new();

        let error = TlsPublicKeyCert::new_from_der(empty_der).unwrap_err();

        assert!(
            matches!(error, TlsPublicKeyCertCreationError { internal_error }
                if internal_error.contains("Error parsing DER")
            )
        );
    }

    #[test]
    fn should_return_error_if_der_malformed() {
        let malformed_der = vec![42u8; 5];

        let error = TlsPublicKeyCert::new_from_der(malformed_der).unwrap_err();

        assert!(
            matches!(error, TlsPublicKeyCertCreationError { internal_error }
                if internal_error.contains("Error parsing DER")
            )
        );
    }

    #[test]
    fn should_deserialize_from_serialized() {
        let cert = TlsPublicKeyCert::new_from_x509(generate_ed25519_cert().1).unwrap();

        let serialized = json5::to_string(&cert).unwrap();

        let deserialized: TlsPublicKeyCert = json5::from_str(&serialized).unwrap();

        assert_eq!(cert, deserialized);
    }

    #[test]
    fn should_deserialize_from_good_der() {
        // Generated by println!-ing during `should_deserialize_from_serialized`.
        let serialized = "{\"certificate_der\":[48,129,222,48,129,145,160,3,2,1,2,2,19,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,\
                                                48,5,6,3,43,101,112,48,16,49,14,48,12,6,3,85,4,3,12,5,83,112,111,99,107,48,30,23,13,50,49,48,54,\
                                                49,55,49,57,51,54,48,50,90,23,13,50,50,48,54,49,55,49,57,51,54,48,50,90,48,16,49,14,48,12,6,3,85,\
                                                4,3,12,5,83,112,111,99,107,48,42,48,5,6,3,43,101,112,3,33,0,179,121,158,74,152,87,17,68,103,148,\
                                                170,106,118,198,73,14,25,89,227,113,57,48,124,13,15,165,136,169,55,23,138,33,48,5,6,3,43,101,112,\
                                                3,65,0,145,75,148,165,172,2,132,83,249,99,84,238,73,0,161,205,135,147,166,67,164,1,43,168,89,210,\
                                                132,246,29,138,88,176,85,61,44,203,176,75,254,16,190,108,172,193,8,74,214,117,167,201,77,168,140,\
                                                119,30,252,78,182,191,48,97,230,28,5]}";

        let result: Result<TlsPublicKeyCert, json5::Error> = json5::from_str(serialized);

        assert!(result.is_ok());

        let deserialized = result.unwrap();
        let subj_name = deserialized.as_x509().subject_name();
        let subj_name = format!("{:?}", subj_name);
        assert_eq!(subj_name, "[commonName = \"Spock\"]");
    }

    #[test]
    fn should_fail_to_deserialize_malformed_der() {
        let bad_serialized = "{\"certificate_der\":[31,41,59,26]}";

        let error: Result<TlsPublicKeyCert, json5::Error> = json5::from_str(bad_serialized);
        assert!(matches!(error, Err(json5::Error::Message { msg, .. } )
            if msg.contains("TlsPublicKeyCertCreationError")
        ));
    }

    #[test]
    fn should_serialize_to_backwards_compatible_for_config() {
        // Older versions of config objects used X509PublicKeyCert,
        // rather than TlsPublicKeyCert.
        // Also, config uses JSON5.
        use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;

        let cert = TlsPublicKeyCert::new_from_x509(generate_ed25519_cert().1).unwrap();

        let proto_cert = X509PublicKeyCert {
            certificate_der: cert.as_der().clone(),
        };

        let serialized = json5::to_string(&cert).unwrap();
        let proto_serialized = json5::to_string(&proto_cert).unwrap();

        assert_eq!(serialized, proto_serialized);
    }
}

mod allowed_clients {
    use crate::{AllowedClients, AllowedClientsError, SomeOrAllNodes};
    use ic_types::{NodeId, PrincipalId};
    use maplit::btreeset;
    use std::collections::BTreeSet;

    #[test]
    fn should_correctly_construct_with_new() {
        let nodes = SomeOrAllNodes::Some(btreeset! {node_id(1)});

        let allowed_clients = AllowedClients::new(nodes.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &nodes);
    }

    #[test]
    fn should_correctly_construct_with_new_with_nodes() {
        let nodes = btreeset! {node_id(1)};

        let allowed_clients = AllowedClients::new_with_nodes(nodes.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &SomeOrAllNodes::Some(nodes));
    }

    #[test]
    fn should_contain_any_node_in_all_nodes() {
        let all_nodes = SomeOrAllNodes::All;

        assert!(all_nodes.contains(node_id(1)));
        assert!(all_nodes.contains(node_id(7)));
    }

    #[test]
    fn should_contain_correct_nodes_in_some_nodes() {
        let some_nodes = SomeOrAllNodes::Some(btreeset! {node_id(1), node_id(2)});

        assert!(some_nodes.contains(node_id(1)));
        assert!(some_nodes.contains(node_id(2)));
        assert!(!some_nodes.contains(node_id(3)));
    }

    #[test]
    fn should_fail_on_new_if_nodes_empty() {
        let allowed_clients = AllowedClients::new(SomeOrAllNodes::Some(BTreeSet::new()));
        assert_eq!(
            allowed_clients.unwrap_err(),
            AllowedClientsError::ClientsEmpty {}
        );
    }

    #[test]
    fn should_fail_on_new_with_nodes_if_nodes_empty() {
        let allowed_clients = AllowedClients::new_with_nodes(BTreeSet::new());
        assert_eq!(
            allowed_clients.unwrap_err(),
            AllowedClientsError::ClientsEmpty {}
        );
    }

    #[test]
    fn should_contain_correct_node_in_some_nodes_new_with_single_node() {
        let nodes = SomeOrAllNodes::new_with_single_node(node_id(1));
        assert!(matches!(nodes, SomeOrAllNodes::Some (node_set)
            if node_set.len() == 1 && node_set.contains(&node_id(1))
        ));
    }

    fn node_id(id: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(id))
    }
}
