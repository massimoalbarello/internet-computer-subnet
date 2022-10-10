use super::*;
use ic_interfaces_registry::RegistryClientResult;
use ic_protobuf::registry::node::v1::{
    connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord,
};
use ic_registry_keys::make_node_record_key;
use ic_test_utilities::{types::ids::node_test_id, with_test_replica_logger};
use ic_test_utilities_registry::MockRegistryClient;
use ic_types::{registry::RegistryClientError, NodeId, RegistryVersion};
use prost::Message;
use std::net::SocketAddr;

const REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(169);
const NODE_ID: u64 = 4;

/// Generates a `RegistryClient` that produces the given response when queried
/// for the node record of the given node.
///
/// Ideally we would have `MockRegistryClient` also implement the
/// `NodeRegistry` trait, but `mockall` chokes on it due to `NodeRegistry`
/// providing an implementation of `get_transport_info`, which conflicts with
/// that generated by `mockall`. Meaning we have to return bytes instead.
fn registry_returning(
    node_id: NodeId,
    response: RegistryClientResult<Vec<u8>>,
) -> Arc<dyn RegistryClient> {
    let mut registry = MockRegistryClient::new();
    registry
        .expect_get_latest_version()
        .return_const(REGISTRY_VERSION);
    registry
        .expect_get_value()
        .withf(move |key, version| {
            key == make_node_record_key(node_id).as_str() && version == &REGISTRY_VERSION
        })
        .return_const(response);
    Arc::new(registry)
}

/// Returns the protobuf-encoded `NodeRecord`.
fn encoded(node_record: NodeRecord) -> Vec<u8> {
    let mut encoded = vec![];
    node_record.encode(&mut encoded).unwrap();
    encoded
}

#[test]
#[should_panic(
    expected = "Could not retrieve registry record for node hr2go-2qeaa-aaaaa-aaaap-2ai"
)]
fn config_get_value_error() {
    with_test_replica_logger(|log| {
        let registry = registry_returning(
            node_test_id(NODE_ID),
            Err(RegistryClientError::VersionNotAvailable {
                version: REGISTRY_VERSION,
            }),
        );

        XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log);
    });
}

#[test]
fn config_node_not_found() {
    with_test_replica_logger(|log| {
        let registry = registry_returning(node_test_id(NODE_ID), Ok(None));

        assert_eq!(
            XNetEndpointConfig {
                address: SocketAddr::from(([127, 0, 0, 1], 0))
            },
            XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log)
        );
    });
}

#[test]
#[should_panic(
    expected = "Node hr2go-2qeaa-aaaaa-aaaap-2ai XNet endpoint [ConnectionEndpoint { ip_addr: \"dfinity.org\", port: 2197, protocol: Http1 }]: IP address does not parse: dfinity.org"
)]
fn config_invalid_xnet_ip_addr() {
    with_test_replica_logger(|log| {
        let invalid_node_record = NodeRecord {
            xnet_api: vec![ConnectionEndpoint {
                ip_addr: "dfinity.org".into(),
                port: 2197,
                protocol: Protocol::Http1 as i32,
            }],
            ..Default::default()
        };
        let registry = registry_returning(
            node_test_id(NODE_ID),
            Ok(Some(encoded(invalid_node_record))),
        );

        XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log)
    });
}

#[test]
fn config_node_record_xnet_is_none() {
    with_test_replica_logger(|log| {
        let empty_node_record = NodeRecord::default();
        let registry =
            registry_returning(node_test_id(NODE_ID), Ok(Some(encoded(empty_node_record))));

        assert_eq!(
            XNetEndpointConfig {
                address: SocketAddr::from(([127, 0, 0, 1], 0))
            },
            XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log)
        );
    });
}

#[test]
fn config_ipv4_success() {
    with_test_replica_logger(|log| {
        let invalid_node_record = NodeRecord {
            xnet_api: vec![ConnectionEndpoint {
                ip_addr: "192.168.0.4".into(),
                port: 2197,
                protocol: Protocol::Http1 as i32,
            }],
            ..Default::default()
        };
        let registry = registry_returning(
            node_test_id(NODE_ID),
            Ok(Some(encoded(invalid_node_record))),
        );

        assert_eq!(
            XNetEndpointConfig {
                address: SocketAddr::from(([192, 168, 0, 4], 2197))
            },
            XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log)
        );
    });
}

#[test]
fn config_ipv6_success() {
    with_test_replica_logger(|log| {
        let invalid_node_record = NodeRecord {
            xnet_api: vec![ConnectionEndpoint {
                ip_addr: "fde4:8dba:82e1::c4".into(),
                port: 2197,
                protocol: Protocol::Http1 as i32,
            }],
            ..Default::default()
        };
        let registry = registry_returning(
            node_test_id(NODE_ID),
            Ok(Some(encoded(invalid_node_record))),
        );

        assert_eq!(
            XNetEndpointConfig {
                address: SocketAddr::from(([0xfde4, 0x8dba, 0x82e1, 0, 0, 0, 0, 0xc4], 2197))
            },
            XNetEndpointConfig::from(registry, node_test_id(NODE_ID), &log)
        );
    });
}
