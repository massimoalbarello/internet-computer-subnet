use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto::utils::{NodeKeysToGenerate, TempCryptoComponent};
use ic_interfaces_transport::{TransportEvent, TransportEventHandler};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_tls_cert_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpSocket;
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);

// Get a free port on this host to which we can connect transport to.
pub fn get_free_localhost_port() -> std::io::Result<u16> {
    let socket = TcpSocket::new_v4()?;
    // This allows transport to bind to this address,
    //  even though the socket is already bound.
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind("127.0.0.1:0".parse().unwrap())?;
    Ok(socket.local_addr()?.port())
}

pub struct RegistryAndDataProvider {
    pub data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
}

impl RegistryAndDataProvider {
    pub fn new() -> Self {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
        Self {
            data_provider,
            registry,
        }
    }
}

impl Default for RegistryAndDataProvider {
    fn default() -> Self {
        Self::new()
    }
}

pub fn temp_crypto_component_with_tls_keys_in_registry(
    registry_and_data: &RegistryAndDataProvider,
    node_id: NodeId,
) -> TempCryptoComponent {
    let temp_crypto = TempCryptoComponent::builder()
        .with_registry(Arc::clone(&registry_and_data.registry) as Arc<_>)
        .with_node_id(node_id)
        .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
        .build();
    let tls_pubkey_cert = temp_crypto.node_tls_public_key_certificate();
    registry_and_data
        .data_provider
        .add(
            &make_crypto_tls_cert_key(node_id),
            REG_V1,
            Some(tls_pubkey_cert.to_proto()),
        )
        .expect("failed to add TLS cert to registry");
    temp_crypto
}

pub fn create_mock_event_handler() -> (TransportEventHandler, Handle<TransportEvent, ()>) {
    let (service, handle) = tower_test::mock::pair::<TransportEvent, ()>();

    let infallible_service = tower::service_fn(move |request: TransportEvent| {
        let mut service_clone = service.clone();
        async move {
            service_clone
                .ready()
                .await
                .expect("Mocking Infallible service. Waiting for readiness failed.")
                .call(request)
                .await
                .expect("Mocking Infallible service and can therefore not return an error.");
            Ok::<(), Infallible>(())
        }
    });
    (BoxCloneService::new(infallible_service), handle)
}
