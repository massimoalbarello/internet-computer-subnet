use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env_api::{
    HasArtifacts, HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr,
};
use crate::driver::universal_vm::*;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::util::{self, create_and_install};
use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
pub use ic_types::{CanisterId, PrincipalId};
use slog::info;
use std::env;
use std::fs;
use std::net::Ipv6Addr;
use std::time::Duration;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

pub fn get_universal_vm_activation_script() -> String {
    fs::read_to_string("src/canister_http/universal_vm_activation.sh").expect("File not found")
}

pub fn await_nodes_healthy(env: &TestEnv) {
    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

pub fn config(env: TestEnv) {
    // Set up Universal VM with HTTP Bin testing service
    let activate_script = &get_universal_vm_activation_script()[..];
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();
    let _ = insert_file_to_config(
        config_dir.clone(),
        "cert.pem",
        get_environment_variable_value("DEV_ROOT_CA").as_bytes(),
    );
    let _ = insert_file_to_config(
        config_dir.clone(),
        "key.pem",
        get_environment_variable_value("DEV_ROOT_CA_KEY").as_bytes(),
    );

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to set up universal VM");

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(3),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    await_nodes_healthy(&env);
    install_nns_canisters(&env);
}

fn get_environment_variable_value(name: &str) -> String {
    // The environment variable could be a regular variable, or could be a file variable.
    // For file variable, the variable's value is address to a file. In this case, we read the content
    // of the file as the real value of the environment variable.
    // For regular variable, we just directly read the value of the variable.
    let dev_root_ca_value =
        env::var(name).expect("Expected environment variable $DEV_ROOT_CA not found!");
    match fs::read_to_string(dev_root_ca_value.clone()) {
        Ok(content) => content,
        Err(_) => dev_root_ca_value,
    }
}

pub fn get_universal_vm_address(env: &TestEnv) -> Ipv6Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let webserver_ipv6: Ipv6Addr = universal_vm.ipv6;
    info!(&env.logger(), "Webserver has IPv6 {:?}", webserver_ipv6);
    let webserver_ipv4 = deployed_universal_vm
        .block_on_ipv4()
        .expect("Universal VM IPv4 not found.");
    info!(&env.logger(), "Webserver has IPv4 {:?}", webserver_ipv4);
    webserver_ipv6
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
}

pub fn get_runtime_from_node(node: &IcNodeSnapshot) -> Runtime {
    util::runtime_from_url(node.get_public_url())
}

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
) -> Canister<'a> {
    info!(&env.logger(), "Installing proxy_canister.");

    // Create proxy canister with maximum canister cycles.
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let proxy_canister_id = rt.block_on(create_and_install(
        &node.build_default_agent(),
        &env.load_wasm("proxy_canister.wasm"),
    ));
    info!(
        &env.logger(),
        "proxy_canister {} installed", proxy_canister_id
    );
    Canister::new(
        runtime,
        CanisterId::new(PrincipalId::from(proxy_canister_id)).unwrap(),
    )
}
