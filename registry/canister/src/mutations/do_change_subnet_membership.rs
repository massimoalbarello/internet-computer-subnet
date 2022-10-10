use crate::{common::LOG_PREFIX, registry::Registry};

use std::convert::TryFrom;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{NodeId, PrincipalId, SubnetId};

impl Registry {
    /// Changes membership of nodes in a subnet record in the registry.
    ///
    /// This method is called by the governance canister, after a proposal
    /// for modifying a subnet by changing the membership (adding/removing) has been accepted.
    pub fn do_change_subnet_membership(&mut self, payload: ChangeSubnetMembershipPayload) {
        println!(
            "{}do_change_subnet_membership started: {:?}",
            LOG_PREFIX, payload
        );

        let nodes_to_add = payload.node_ids_add.clone();
        let subnet_record = self.get_subnet_or_panic(SubnetId::from(payload.subnet_id));

        let current_subnet_nodes: Vec<NodeId> = subnet_record
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect();

        // Verify that nodes requested to be removed belong to the subnet provided in the payload
        if !payload
            .node_ids_remove
            .iter()
            .all(|n| current_subnet_nodes.contains(n))
        {
            panic!("Nodes that should be removed do not belong to the provided subnet.")
        }

        // Calculate a complete list of nodes in this subnet after the change of subnet membership is executed
        let subnet_membership_after_change = nodes_to_add
            .iter()
            .cloned()
            .chain(current_subnet_nodes)
            .filter(|node_id_in_subnet| {
                payload
                    .node_ids_remove
                    .iter()
                    .all(|node_id_to_remove| node_id_in_subnet != node_id_to_remove)
            })
            .collect();

        let mutations = vec![self.make_replace_subnet_membership_mutation(
            SubnetId::from(payload.subnet_id),
            subnet_membership_after_change,
        )];

        // Check the invariants and apply the mutations if invariants are satisfied
        self.maybe_apply_mutation_internal(mutations);

        println!(
            "{}do_change_subnet_membership finished: {:?}",
            LOG_PREFIX, payload
        );
    }
}

/// The payload of a proposal to change the membership of nodes in an existing subnet.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChangeSubnetMembershipPayload {
    /// The subnet ID to mutate.
    pub subnet_id: PrincipalId,
    /// The list of node IDs that will be added to the subnet.
    pub node_ids_add: Vec<NodeId>,
    /// The list of node IDs that will be removed from the subnet.
    pub node_ids_remove: Vec<NodeId>,
}
