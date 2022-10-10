mod common;

use common::{
    create_mock_event_handler, get_free_localhost_port,
    temp_crypto_component_with_tls_keys_in_registry, RegistryAndDataProvider, REG_V1,
};
use ic_base_types::{NodeId, RegistryVersion};
use ic_config::transport::TransportConfig;
use ic_crypto_tls_interfaces::{TlsClientHandshakeError, TlsHandshake};
use ic_crypto_tls_interfaces_mocks::MockTlsHandshake;
use ic_interfaces_transport::{
    Transport, TransportChannelId, TransportError, TransportEvent, TransportEventHandler,
    TransportPayload,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_transport::{transport::create_transport, transport_h2::create_transport_h2};
use ic_types_test_utils::ids::{NODE_1, NODE_2};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Notify,
};
use tokio::time::Duration;
use tower_test::mock::Handle;

const NODE_ID_1: NodeId = NODE_1;
const NODE_ID_2: NodeId = NODE_2;
const TRANSPORT_CHANNEL_ID: u32 = 1234;

fn setup_test_peer<F>(
    log: ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    node_id: NodeId,
    port: u16,
    registry_version: RegistryVersion,
    registry_and_data: &mut RegistryAndDataProvider,
    mut crypto_factory: F,
) -> (Arc<dyn Transport>, Handle<TransportEvent, ()>, SocketAddr)
where
    F: FnMut(&mut RegistryAndDataProvider, NodeId) -> Arc<dyn TlsHandshake + Send + Sync>,
{
    let crypto = crypto_factory(registry_and_data, node_id);
    let config = TransportConfig {
        node_ip: "0.0.0.0".to_string(),
        legacy_flow_tag: TRANSPORT_CHANNEL_ID,
        listening_port: port,
        send_queue_size: 10,
    };
    let peer = create_transport(
        node_id,
        config,
        registry_version,
        MetricsRegistry::new(),
        crypto,
        rt_handle,
        log,
    );
    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
    let (event_handler, mock_handle) = create_mock_event_handler();
    peer.set_event_handler(event_handler);
    (peer, mock_handle, addr)
}

#[test]
fn test_start_connection_between_two_peers() {
    test_start_connection_between_two_peers_impl(false);
    //test_start_connection_between_two_peers_impl(true);
}

fn test_start_connection_between_two_peers_impl(use_h2: bool) {
    with_test_replica_logger(|logger| {
        let registry_version = REG_V1;

        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, mut peer_a_receiver) = channel(1);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(1);
        let event_handler_2 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_b_sender);

        let (_control_plane_1, _control_plane_2) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            10,
            event_handler_1,
            event_handler_2,
            use_h2,
        );

        assert_eq!(peer_a_receiver.blocking_recv(), Some(true));
        assert_eq!(peer_b_receiver.blocking_recv(), Some(true));
    });
}

/*
Verifies that transport suffers "head of line problem" when peer is slow to consume messages.
- Peer A sends Peer B message, which will work fine.
- Then, B's event handler blocks to prevent B from reading additional messages.
- A sends a few more messages, but at this point queue will be full.
- Finally, we unblock B's event handler, and confirm all in-flight messages are delivered.
*/
#[test]
fn head_of_line_test() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(5);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(5);

        let notify = Arc::new(Notify::new());
        let listener = notify.clone();

        // Create event handler that blocks on message
        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let (_peer_a, _peer_b, messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            false,
        );

        // Unblock event handler and confirm in-flight messages are received.
        notify.notify_one();

        for _ in 1..=messages_sent {
            assert_eq!(peer_b_receiver.blocking_recv(), Some(true));
        }
    });
}

/*
Establish connection with 2 peers, A and B.  Send message from A->B and B->A and confirm both are received
*/
#[test]
fn test_basic_message_send() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, mut peer_a_receiver) = channel(1);
        let peer_a_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(1);
        let peer_b_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_b_sender);

        let (peer_a, peer_b) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            peer_a_event_handler,
            peer_b_event_handler,
            false,
        );

        let msg_1 = TransportPayload(vec![0xa; 1000000]);
        let msg_2 = TransportPayload(vec![0xb; 1000000]);
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        // A sends message to B
        let res = peer_a.send(&NODE_ID_2, channel_id, msg_1.clone());
        assert_eq!(res, Ok(()));
        assert_eq!(peer_b_receiver.blocking_recv(), Some(msg_1));

        // B sends message to A
        let res2 = peer_b.send(&NODE_ID_1, channel_id, msg_2.clone());
        assert_eq!(res2, Ok(()));
        assert_eq!(peer_a_receiver.blocking_recv(), Some(msg_2));
    });
}

/*
Establish connection with 2 peers, A and B.  Confirm that connection stays alive even when
no messages are being sent. (In current implementation, this is ensured by heartbeats)
*/
#[test]
fn test_idle_connection_active() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(1);
        let peer_a_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(1);
        let peer_b_event_handler =
            setup_message_ack_event_handler(rt.handle().clone(), peer_b_sender);

        let (peer_a, _peer_b) = start_connection_between_two_peers(
            rt.handle().clone(),
            logger,
            registry_version,
            1,
            peer_a_event_handler,
            peer_b_event_handler,
            false,
        );
        std::thread::sleep(Duration::from_secs(20));

        let msg_1 = TransportPayload(vec![0xa; 1000000]);
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

        // A sends message to B to verify that the connection is still alive
        let res = peer_a.send(&NODE_ID_2, channel_id, msg_1.clone());
        assert_eq!(res, Ok(()));
        assert_eq!(peer_b_receiver.blocking_recv(), Some(msg_1));
    });
}

/*
Tests that clearing send queue unblocks queue from receiving more messages.
Set Peer B to block event handler so no messages are consumed
A sends messages until send queue full, confirm error
Call clear send queue
A sends another message, confirm queue can accept more messages
*/
#[test]
fn test_clear_send_queue() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();

        let (peer_a_sender, _peer_a_receiver) = channel(10);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(10);

        let listener = Arc::new(Notify::new());

        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let queue_size = 10;

        let (peer_a, _peer_b, _messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            queue_size,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            false,
        );

        peer_a.clear_send_queues(&NODE_ID_2);

        // Confirm that queue is completely clear by sending messages = queue size
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);
        let normal_msg = TransportPayload(vec![0xb; 1000000]);

        for _ in 1..queue_size {
            let res3 = peer_a.send(&NODE_ID_2, channel_id, normal_msg.clone());
            assert_eq!(res3, Ok(()));
        }
    });
}

/*
Tests that draining the send queue unblocks queue from receiving more messages.
Set Peer B to block event handler so no messages are consumed
A sends messages until send queue full, confirm error
Call clear send queue
A sends another message, confirm queue can accept more messages
*/
#[test]
fn test_drain_send_queue() {
    let registry_version = REG_V1;
    with_test_replica_logger(|logger| {
        // Setup registry and crypto component
        let rt = tokio::runtime::Runtime::new().unwrap();
        let queue_size = 10;

        let (peer_a_sender, _peer_a_receiver) = channel(10);
        let event_handler_1 = setup_peer_up_ack_event_handler(rt.handle().clone(), peer_a_sender);

        let (peer_b_sender, mut peer_b_receiver) = channel(10);

        let listener = Arc::new(Notify::new());
        let notify = listener.clone();

        let hol_event_handler =
            setup_blocking_event_handler(rt.handle().clone(), peer_b_sender, listener);

        let (peer_a, _peer_b, messages_sent) = trigger_and_test_send_queue_full(
            rt.handle().clone(),
            logger,
            registry_version,
            queue_size,
            event_handler_1,
            hol_event_handler,
            &mut peer_b_receiver,
            false,
        );

        // Unblock event handler to drain queue and confirm in-flight messages are received.
        notify.notify_one();

        for _ in 1..=messages_sent {
            assert_eq!(peer_b_receiver.blocking_recv(), Some(true));
        }

        // Confirm that queue is clear by sending messages = queue size
        let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);
        let normal_msg = TransportPayload(vec![0xb; 1000000]);

        for _ in 1..queue_size {
            let res3 = peer_a.send(&NODE_ID_2, channel_id, normal_msg.clone());
            assert_eq!(res3, Ok(()));
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

// helper functions

fn setup_peer_up_ack_event_handler(
    rt: tokio::runtime::Handle,
    connected: Sender<bool>,
) -> TransportEventHandler {
    let (event_handler, mut handle) = create_mock_event_handler();
    rt.spawn(async move {
        loop {
            if let Some(req) = handle.next_request().await {
                let (event, rsp) = req;
                if let TransportEvent::PeerUp(_) = event {
                    connected
                        .try_send(true)
                        .expect("Channel capacity should not be reached");
                }
                rsp.send_response(());
            }
        }
    });
    event_handler
}

fn setup_message_ack_event_handler(
    rt: tokio::runtime::Handle,
    connected: Sender<TransportPayload>,
) -> TransportEventHandler {
    let (event_handler, mut handle) = create_mock_event_handler();

    rt.spawn(async move {
        loop {
            let (event, rsp) = handle.next_request().await.unwrap();
            match event {
                TransportEvent::Message(msg) => {
                    connected.send(msg.payload).await.expect("Channel busy");
                }
                TransportEvent::PeerUp(_) => {}
                TransportEvent::PeerDown(_) => {}
            };
            rsp.send_response(());
        }
    });
    event_handler
}

fn setup_blocking_event_handler(
    rt: tokio::runtime::Handle,
    sender: Sender<bool>,
    listener: Arc<Notify>,
) -> TransportEventHandler {
    let blocking_msg = TransportPayload(vec![0xa; 1000000]);
    let (event_handler, mut handle) = create_mock_event_handler();

    rt.spawn(async move {
        loop {
            let (event, rsp) = handle.next_request().await.unwrap();
            match event {
                TransportEvent::Message(msg) => {
                    sender.send(true).await.expect("Channel busy");
                    // This will block the read task
                    if msg.payload == blocking_msg {
                        listener.notified().await;
                    }
                }
                TransportEvent::PeerUp(_) => {}
                TransportEvent::PeerDown(_) => {}
            };
            rsp.send_response(());
        }
    });
    event_handler
}

#[test]
fn test_single_transient_failure_of_tls_client_handshake() {
    with_test_replica_logger(|log| {
        let mut registry_and_data = RegistryAndDataProvider::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let rt_handle = rt.handle().clone();

        let crypto_factory_with_single_tls_handshake_client_failures =
            |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
                let mut mock_client_tls_handshake = MockTlsHandshake::new();
                let rt_handle = rt_handle.clone();

                let crypto = Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                    registry_and_data,
                    node_id,
                ));

                mock_client_tls_handshake
                    .expect_perform_tls_client_handshake()
                    .times(1)
                    .returning({
                        move |_tcp_stream: TcpStream,
                              _server: NodeId,
                              _registry_version: RegistryVersion| {
                            Err(TlsClientHandshakeError::HandshakeError {
                                internal_error: "transient".to_string(),
                            })
                        }
                    });

                mock_client_tls_handshake
                    .expect_perform_tls_client_handshake()
                    .times(1)
                    .returning(
                        move |tcp_stream: TcpStream,
                              server: NodeId,
                              registry_version: RegistryVersion| {
                            let rt_handle = rt_handle.clone();
                            let crypto = crypto.clone();

                            tokio::task::block_in_place(move || {
                                let rt_handle = rt_handle.clone();

                                rt_handle.block_on(async move {
                                    crypto
                                        .perform_tls_client_handshake(
                                            tcp_stream,
                                            server,
                                            registry_version,
                                        )
                                        .await
                                })
                            })
                        },
                    );

                Arc::new(mock_client_tls_handshake) as Arc<dyn TlsHandshake + Send + Sync>
            };

        let crypto_factory = |registry_and_data: &mut RegistryAndDataProvider, node_id: NodeId| {
            Arc::new(temp_crypto_component_with_tls_keys_in_registry(
                registry_and_data,
                node_id,
            )) as Arc<dyn TlsHandshake + Send + Sync>
        };

        let peer1_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_1, mut mock_handle_peer_1, peer_1_addr) = setup_test_peer(
            log.clone(),
            rt.handle().clone(),
            NODE_1,
            peer1_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory_with_single_tls_handshake_client_failures,
        );
        let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
        let (peer_2, mut mock_handle_peer_2, peer_2_addr) = setup_test_peer(
            log,
            rt.handle().clone(),
            NODE_2,
            peer2_port,
            REG_V1,
            &mut registry_and_data,
            crypto_factory,
        );
        registry_and_data.registry.update_to_latest_version();

        let (connected_1, mut done_1) = channel(1);
        let (connected_2, mut done_2) = channel(1);
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_1.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_1.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        rt.spawn(async move {
            let (event, rsp) = mock_handle_peer_2.next_request().await.unwrap();
            if let TransportEvent::PeerUp(_) = event {
                connected_2.try_send(true).unwrap()
            }
            rsp.send_response(());
        });
        assert!(peer_1
            .start_connection(&NODE_ID_2, peer_2_addr, REG_V1)
            .is_ok());

        assert!(peer_2
            .start_connection(&NODE_ID_1, peer_1_addr, REG_V1)
            .is_ok());
        assert_eq!(done_1.blocking_recv(), Some(true));
        assert_eq!(done_2.blocking_recv(), Some(true));
    });
}

fn start_connection_between_two_peers(
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    registry_version: RegistryVersion,
    send_queue_size: usize,
    event_handler_1: TransportEventHandler,
    event_handler_2: TransportEventHandler,
    use_h2: bool,
) -> (Arc<dyn Transport>, Arc<dyn Transport>) {
    // Setup registry and crypto component
    let registry_and_data = RegistryAndDataProvider::new();
    let crypto_1 = temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_1);
    let crypto_2 = temp_crypto_component_with_tls_keys_in_registry(&registry_and_data, NODE_ID_2);
    registry_and_data.registry.update_to_latest_version();

    let peer1_port = get_free_localhost_port().expect("Failed to get free localhost port");
    let peer_a_config = TransportConfig {
        node_ip: "127.0.0.1".to_string(),
        listening_port: peer1_port,
        legacy_flow_tag: TRANSPORT_CHANNEL_ID,
        send_queue_size,
    };

    let peer_a = create_transport_obj(
        NODE_ID_1,
        peer_a_config,
        registry_version,
        Arc::new(crypto_1),
        rt_handle.clone(),
        logger.clone(),
        use_h2,
    );

    peer_a.set_event_handler(event_handler_1);

    let peer2_port = get_free_localhost_port().expect("Failed to get free localhost port");
    let peer_b_config = TransportConfig {
        node_ip: "127.0.0.1".to_string(),
        listening_port: peer2_port,
        legacy_flow_tag: TRANSPORT_CHANNEL_ID,
        send_queue_size,
    };

    let peer_b = create_transport_obj(
        NODE_ID_2,
        peer_b_config,
        registry_version,
        Arc::new(crypto_2),
        rt_handle,
        logger,
        use_h2,
    );
    peer_b.set_event_handler(event_handler_2);
    let peer_2_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer2_port)).unwrap();

    peer_a
        .start_connection(&NODE_ID_2, peer_2_addr, REG_V1)
        .expect("start_connection");

    let peer_1_addr = SocketAddr::from_str(&format!("127.0.0.1:{}", peer1_port)).unwrap();
    peer_b
        .start_connection(&NODE_ID_1, peer_1_addr, REG_V1)
        .expect("start_connection");

    (peer_a, peer_b)
}

fn trigger_and_test_send_queue_full(
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    registry_version: RegistryVersion,
    send_queue_size: usize,
    event_handler_a: TransportEventHandler,
    event_handler_b: TransportEventHandler,
    peer_b_receiver: &mut Receiver<bool>,
    use_h2: bool,
) -> (Arc<dyn Transport>, Arc<dyn Transport>, i32) {
    let (peer_a, _peer_b) = start_connection_between_two_peers(
        rt_handle,
        logger,
        registry_version,
        send_queue_size,
        event_handler_a,
        event_handler_b,
        use_h2,
    );
    let channel_id = TransportChannelId::from(TRANSPORT_CHANNEL_ID);

    let blocking_msg = TransportPayload(vec![0xa; 1000000]);
    let normal_msg = TransportPayload(vec![0xb; 1000000]);

    // A sends message to B
    let res = peer_a.send(&NODE_ID_2, channel_id, blocking_msg);
    assert_eq!(res, Ok(()));
    assert_eq!(peer_b_receiver.blocking_recv(), Some(true));

    // Send messages from A->B until TCP Queue is full
    let _temp = normal_msg.clone();
    let mut messages_sent = 0;
    loop {
        if let Err(TransportError::SendQueueFull(ref _temp)) =
            peer_a.send(&NODE_ID_2, channel_id, normal_msg.clone())
        {
            break;
        }
        messages_sent += 1;
        std::thread::sleep(Duration::from_millis(10));
    }
    let res2 = peer_a.send(&NODE_ID_2, channel_id, normal_msg.clone());
    assert_eq!(res2, Err(TransportError::SendQueueFull(normal_msg)));

    (peer_a, _peer_b, messages_sent)
}

fn create_transport_obj(
    node_id: NodeId,
    transport_config: TransportConfig,
    registry_version: RegistryVersion,
    crypto: Arc<dyn TlsHandshake + Send + Sync>,
    rt_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    use_h2: bool,
) -> Arc<dyn Transport> {
    if use_h2 {
        create_transport_h2(
            node_id,
            transport_config,
            registry_version,
            MetricsRegistry::new(),
            crypto,
            rt_handle,
            logger,
        )
    } else {
        create_transport(
            node_id,
            transport_config,
            registry_version,
            MetricsRegistry::new(),
            crypto,
            rt_handle,
            logger,
        )
    }
}
