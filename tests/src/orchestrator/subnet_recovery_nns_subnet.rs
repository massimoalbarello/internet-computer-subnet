/* tag::catalog[]

Title:: Subnet Recovery Test (NNS subnet, same nodes)

Goal::
Ensure that the subnet recovery of an NNS subnet without changing the node membership works.

Runbook::
. Start IC with NNS and then break the NNS subnet.
. Use ic-replay to update registry to include a new replica version, and produce a new CUP.
  Note: ic-replay is not used directly in this test; NNSRecoverySameNodes provides most of its functionality. See enum StepType for the list of steps
. Load the new CUP (together with registry local store and canister states) manually on all NNS nodes.
. Observe that NNS subnet restarts and continues functioning.

Success::
. NNS subnet is functional after the recovery.

end::catalog[] */

use super::utils::rw_message::install_nns_and_universal_canisters;
use crate::driver::driver_setup::{
    IcSetup, SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnvAttribute;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::utils::rw_message::{
    can_install_canister_with_retries, can_read_msg, cannot_store_msg, store_message,
};
use ic_recovery::nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs};
use ic_recovery::{file_sync_helper, get_node_metrics, RecoveryArgs};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::convert::TryFrom;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 3;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_universal_canisters(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topo_snapshot = env.topology_snapshot();

    let ic_version = IcSetup::read_attribute(&env).initial_replica_version;
    let ic_version_str = ic_version.to_string();
    info!(logger, "IC_VERSION_ID: {}", ic_version_str);

    // identifies the version of the replica after the recovery
    let working_version = ReplicaVersion::try_from(format!("{}-test", ic_version_str)).unwrap();
    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    info!(
        logger,
        "ssh_authorized_priv_keys_dir: {:?}", ssh_authorized_priv_keys_dir
    );
    info!(
        logger,
        "ssh_authorized_pub_keys_dir: {:?}", ssh_authorized_pub_keys_dir
    );

    // choose a node from the nns subnet
    let mut nns_nodes = topo_snapshot.root_subnet().nodes();
    let upload_node = nns_nodes.next().expect("there is no NNS node");

    info!(
        logger,
        "Selected NNS node, also for upload: {} ({:?})",
        upload_node.node_id,
        upload_node.get_ip_addr()
    );

    // get another one for the download node
    let download_node = nns_nodes.next().expect("there is no NNS node");
    info!(
        logger,
        "NNS node for download: {} ({:?})",
        download_node.node_id,
        download_node.get_ip_addr()
    );

    info!(logger, "Ensure NNS subnet is functional");
    let msg = "subnet recovery works!";
    let app_can_id = store_message(&upload_node.get_public_url(), msg);
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(ADMIN))
        .expect("Couldn't read public key");

    let tempdir = tempfile::tempdir().expect("Could not create a temp dir");

    let recovery_args = RecoveryArgs {
        dir: tempdir.path().to_path_buf(),
        nns_url: upload_node.get_public_url(),
        replica_version: Some(ic_version),
        key_file: Some(ssh_authorized_priv_keys_dir.join(ADMIN)),
    };

    // unlike during a production recovery using the CLI, here we already know all of parameters ahead of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: topo_snapshot.root_subnet_id(),
        upgrade_version: Some(working_version),
        pub_key: Some(pub_key),
        download_node: Some(download_node.get_ip_addr()),
        upload_node: Some(upload_node.get_ip_addr()),
    };

    let mut subnet_recovery =
        NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args, true);

    // let's take f+1 nodes and break them.
    let f = (SUBNET_SIZE - 1) / 3;
    info!(
        logger,
        "Breaking the NNS subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = nns_nodes.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        // simulate subnet failure by breaking the replica process, but not the orchestrator
        subnet_recovery
        .get_recovery_api()
        .execute_ssh_command(
            "admin",
            node.get_ip_addr(),
            "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica",
        )
        .expect("couldn't run ssh command");
    }

    info!(logger, "Ensure the subnet works in read mode");
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));

    let up_node_metrics = get_node_metrics(&logger, &upload_node.get_ip_addr())
        .expect("Missing metrics for upload node");
    let dn_node_metrics = get_node_metrics(&logger, &download_node.get_ip_addr())
        .expect("Missing metrics for download node");
    if dn_node_metrics.finalization_height < up_node_metrics.finalization_height {
        // swap the two nodes, so that download one has highest height in the subnet
        subnet_recovery.params.download_node = Some(upload_node.get_ip_addr());
        subnet_recovery.params.upload_node = Some(download_node.get_ip_addr());
        subnet_recovery.recovery.admin_helper.nns_url = download_node.get_public_url();
    }

    info!(
        logger,
        "Starting recovery of the NNS subnet {}",
        topo_snapshot.root_subnet().subnet_id.to_string()
    );

    // go over all steps of the NNS recovery
    for (step_type, step) in subnet_recovery {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }
    info!(logger, "NNS recovery has finished");

    // check that the network functions
    upload_node.await_status_is_healthy().unwrap();

    info!(logger, "Wait for state sync to complete");
    can_install_canister_with_retries(&upload_node.get_public_url(), &logger, secs(600), secs(10));

    info!(logger, "Ensure the old message is still readable");
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));
    let new_msg = "subnet recovery still works!";
    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    let new_app_can_id = store_message(&upload_node.get_public_url(), new_msg);
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        new_app_can_id,
        new_msg
    ));
}
