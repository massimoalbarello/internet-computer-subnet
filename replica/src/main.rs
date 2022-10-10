use ic_config::crypto::CryptoConfig;
use std::path::PathBuf;
use ic_test_utilities::{
    types::ids::subnet_test_id,
    self_validating_payload_builder::FakeSelfValidatingPayloadBuilder,
    xnet_payload_builder::FakeXNetPayloadBuilder,
    message_routing::FakeMessageRouting,
};
use ic_test_utilities_registry::{test_subnet_record, setup_registry};
use ic_logger::replica_logger::no_op_logger;
use ic_crypto::{CryptoComponent, CryptoComponentFatClient};
use ic_types::{
    NodeId,
    SubnetId,
    CryptoHashOfState,
    crypto::CryptoHash,
};
use ic_interfaces::{
    self_validating_payload::SelfValidatingPayloadBuilder,
    messaging::{XNetPayloadBuilder, MessageRouting},
    crypto::{Crypto, IngressSigVerifier},
};
use ic_consensus::{
    consensus::ConsensusCrypto,
    certification,
    consensus::mocks::{dependencies_with_subnet_params, Dependencies},
};
use ic_config::consensus::ConsensusConfig;
use ic_logger::replica_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_interfaces_state_manager::StateManager;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::StateManagerImpl;
use tempfile::Builder;
use ic_replica::setup;
use ic_execution_environment::ExecutionServices;
use ic_registry_client_fake::FakeRegistryClient;
use std::sync::Arc;
use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
use ic_replica_setup_ic_network::{
    init_artifact_pools, P2PStateSyncClient,
};
use ic_config::{artifact_pool::ArtifactPoolConfig, subnet_config::SubnetConfig, Config};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_p2p::{fetch_gossip_config, AdvertBroadcaster};
use ic_test_utilities_registry::FakeLocalStoreCertifiedTimeReader;
use ic_interfaces_registry::LocalStoreCertifiedTimeReader;
use ic_interfaces_canister_http_adapter_client::CanisterHttpAdapterClient;
use ic_replica_setup_ic_network::setup_artifact_manager;

fn main() {

    let registry = {
        let subnet_id = subnet_test_id(0);
        let subnet_record = test_subnet_record();
        let versions = vec![(1 as u64, subnet_record)];
        setup_registry(subnet_id, versions)
    };

    let crypto = {
        let crypto_config = CryptoConfig::new(PathBuf::from(r"C:\windows\system32.dll"));
        let rt_main = None;
        let replica_logger = no_op_logger();
        let metrics_registry = None;
        CryptoComponent::new(
            &crypto_config,
            rt_main,
            Arc::clone(&registry),
            replica_logger.clone(),
            metrics_registry,
        )
    };

    let node_id: NodeId = crypto.get_node_id();

    let crypto = Arc::new(crypto) as Arc<dyn Crypto>;

    let consensus_crypto = Arc::clone(&crypto) as Arc<dyn ConsensusCrypto>;

    let certifier_crypto = Arc::clone(&crypto) as Arc<dyn certification::CertificationCrypto>;

    let ingress_sig_crypto = Arc::clone(&crypto) as Arc<dyn IngressSigVerifier + Send + Sync>;

    let subnet_id: SubnetId = subnet_test_id(0);

    let consensus_config = ConsensusConfig::default();

    let replica_logger: ReplicaLogger = no_op_logger();

    let metrics_registry = MetricsRegistry::new();

    let registry_client = Arc::clone(&registry);

    let (state_manager, artifact_pool_config) = {
        let tempdir = Builder::new().prefix("persistent-pool").tempdir().unwrap();
        let artifact_pool_config = ArtifactPoolConfig::new(tempdir.path().to_path_buf());
        // TODO: decide whether to use 'registry' and 'crypto' provided here or create them separately as done above
        let Dependencies {
            pool,
            membership,
            // registry,
            // crypto,
            time_source,
            replica_config,
            state_manager,
            dkg_pool,
            ecdsa_pool,
            ..
        } = dependencies_with_subnet_params(artifact_pool_config, subnet_id, vec![(1, record)]);
        state_manager
            .get_mut()
            .expect_latest_certified_height()
            .return_const(Height::from(0));
        state_manager
            .get_mut()
            .expect_get_state_hash_at()
            .return_const(Ok(CryptoHashOfState::from(CryptoHash(Vec::new()))));
        (state_manager as Arc<dyn StateManager<State = ReplicatedState>>, artifact_pool_config)
    };
    
    let state_sync_client = P2PStateSyncClient::Client(Arc::clone(&state_manager) as Arc<StateManagerImpl>);

    let xnet_payload_builder = Arc::new(FakeXNetPayloadBuilder::new()) as Arc<dyn XNetPayloadBuilder>;

    let self_validating_payload_builder = Arc::new(FakeSelfValidatingPayloadBuilder::new()) as Arc<dyn SelfValidatingPayloadBuilder>;

    let message_router = Arc::new(FakeMessageRouting::new()) as Arc<dyn MessageRouting>;

    let config = {
        let replica_args = setup::parse_args();
        let config_source = setup::get_config_source(&replica_args);
        let tmpdir = tempfile::Builder::new()
            .prefix("ic_config")
            .tempdir()
            .unwrap();
        Config::load_with_tmpdir(config_source, tmpdir.path().to_path_buf())
    };

    let (ingress_history_reader, cycles_account_manager, execution_services) = {
        let subnet_type = SubnetType::Application;
        let subnet_config = SubnetConfig::default_application_subnet();
        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));
        let execution_services = ExecutionServices::setup_execution(
            replica_logger.clone(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            subnet_config.scheduler_config,
            config.hypervisor.clone(),
            Arc::clone(&cycles_account_manager),
            Arc::clone(&state_manager) as Arc<_>,
        );
        (execution_services.ingress_history_reader, cycles_account_manager, execution_services)
    };

    let artifact_pools = {
        let catch_up_package = None;
        init_artifact_pools(
            subnet_id,
            artifact_pool_config,
            metrics_registry.clone(),
            replica_logger.clone(),
            catch_up_package,
        )
    };

    let malicious_flags = config.malicious_behaviour.malicious_flags.clone();

    let local_store_time_reader = {
        Some(Arc::new(FakeLocalStoreCertifiedTimeReader::new(
            time_source.clone(),
        ))) as Option<Arc<dyn LocalStoreCertifiedTimeReader>>
    };

    let registry_poll_delay_duration_ms = config.nns_registry_replicator.poll_delay_duration_ms;

    // TODO: modify 'advert_broadcaster' to use our version of P2P which sends artifacts instead of adverts
    let advert_broadcaster = {
        let gossip_config = fetch_gossip_config(registry_client.clone(), subnet_id);
        AdvertBroadcaster::new(log.clone(), &metrics_registry, gossip_config.clone())
    };

    let canister_http_adapter_client = {
        let rt_main = tokio::runtime::Runtime::new().unwrap();
        let rt_handle = rt_main.handle();
        ic_canister_http_adapter_client::setup_canister_http_client(
            rt_handle.clone(),
            &metrics_registry,
            config.adapters_config,
            execution_services.anonymous_query_handler.clone(),
            replica_logger.clone(),
        ) as CanisterHttpAdapterClient
    };

    let artifact_manager = setup_artifact_manager(
        node_id,
        crypto,
        consensus_crypto,
        certifier_crypto,
        ingress_sig_crypto,
        subnet_id,
        consensus_config,
        replica_logger.clone(),
        metrics_registry,
        registry_client,
        state_manager,
        state_sync_client,
        xnet_payload_builder,
        self_validating_payload_builder,
        message_router,
        ingress_history_reader,
        &artifact_pools,
        malicious_flags,
        cycles_account_manager,
        local_store_time_reader,
        registry_poll_delay_duration_ms,
        advert_broadcaster,
        canister_http_adapter_client,
    ).unwrap();
}