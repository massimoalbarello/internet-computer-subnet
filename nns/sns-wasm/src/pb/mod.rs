use crate::pb::v1::{
    add_wasm_response, AddWasmResponse, GetNextSnsVersionRequest, GetNextSnsVersionResponse,
    SnsCanisterIds, SnsCanisterType, SnsUpgrade, SnsVersion, SnsWasm, SnsWasmError,
    SnsWasmStableIndex, StableCanisterState, UpgradePath as StableUpgradePath,
};
use crate::sns_wasm::{vec_to_hash, SnsWasmCanister, UpgradePath};
use crate::stable_memory::SnsWasmStableMemory;
use ic_base_types::CanisterId;
use ic_cdk::api::stable::StableMemory;
use ic_crypto_sha::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fmt::{Display, Write};
use std::str::FromStr;

#[allow(clippy::all)]
#[path = "../../gen/ic_sns_wasm.pb.v1.rs"]
pub mod v1;

/// Converts a sha256 hash into a hex string representation
pub fn hash_to_hex_string(hash: &[u8; 32]) -> String {
    let mut result_hash = String::new();
    for b in hash {
        let _ = write!(result_hash, "{:02X}", b);
    }
    result_hash
}

impl AddWasmResponse {
    pub fn error(message: String) -> Self {
        Self {
            result: Some(add_wasm_response::Result::Error(SnsWasmError { message })),
        }
    }
}

impl SnsWasm {
    /// Calculate the sha256 hash for the wasm.
    pub fn sha256_hash(&self) -> [u8; 32] {
        Sha256::hash(&self.wasm)
    }

    /// Provide string representation of the sha256 hash for the wasm.
    pub fn sha256_string(&self) -> String {
        let bytes = self.sha256_hash();
        hash_to_hex_string(&bytes)
    }

    /// Return the SnsCanisterType if it's valid, else return an error
    pub fn checked_sns_canister_type(&self) -> Result<SnsCanisterType, String> {
        match SnsCanisterType::from_i32(self.canister_type) {
            None => Err(
                "Invalid value for SnsWasm::canister_type.  See documentation for valid values"
                    .to_string(),
            ),
            Some(canister_type) => {
                if canister_type == SnsCanisterType::Unspecified {
                    Err("SnsWasm::canister_type cannot be 'Unspecified' (0).".to_string())
                } else {
                    Ok(canister_type)
                }
            }
        }
    }
}

impl From<SnsVersion> for GetNextSnsVersionRequest {
    fn from(version: SnsVersion) -> GetNextSnsVersionRequest {
        GetNextSnsVersionRequest {
            current_version: Some(version),
        }
    }
}

impl From<SnsVersion> for GetNextSnsVersionResponse {
    fn from(version: SnsVersion) -> GetNextSnsVersionResponse {
        GetNextSnsVersionResponse {
            next_version: Some(version),
        }
    }
}

impl Display for SnsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut versions_str = HashMap::<&str, String>::new();

        versions_str.insert("Root", hex::encode(&self.root_wasm_hash));
        versions_str.insert("Governance", hex::encode(&self.governance_wasm_hash));
        versions_str.insert("Ledger", hex::encode(&self.ledger_wasm_hash));
        versions_str.insert("Swap", hex::encode(&self.swap_wasm_hash));
        versions_str.insert("Archive", hex::encode(&self.archive_wasm_hash));

        let json = serde_json::to_string(&versions_str)
            .unwrap_or_else(|e| format!("Unable to serialize SnsVersion: {}", e));

        write!(f, "{}", json)
    }
}

impl SnsCanisterIds {
    /// Get Root CanisterId
    pub fn root(&self) -> CanisterId {
        CanisterId::new(self.root.unwrap()).unwrap()
    }
    /// Get Governance CanisterId
    pub fn governance(&self) -> CanisterId {
        CanisterId::new(self.governance.unwrap()).unwrap()
    }
    /// Get Ledger CanisterId
    pub fn ledger(&self) -> CanisterId {
        CanisterId::new(self.ledger.unwrap()).unwrap()
    }
    /// Get Swap CanisterId
    pub fn swap(&self) -> CanisterId {
        CanisterId::new(self.swap.unwrap()).unwrap()
    }

    /// Get Index CanisterId
    pub fn index(&self) -> CanisterId {
        CanisterId::new(self.index.unwrap()).unwrap()
    }
}

impl TryFrom<SnsCanisterIds> for ic_sns_init::SnsCanisterIds {
    type Error = String;

    fn try_from(ids: SnsCanisterIds) -> Result<Self, Self::Error> {
        Ok(ic_sns_init::SnsCanisterIds {
            root: ids.root.ok_or_else(|| "Root missing".to_string())?,
            governance: ids
                .governance
                .ok_or_else(|| "Governance missing".to_string())?,
            ledger: ids.ledger.ok_or_else(|| "Ledger missing".to_string())?,
            swap: ids.swap.ok_or_else(|| "Swap missing".to_string())?,
            index: ids.index.ok_or_else(|| "Index missing".to_string())?,
        })
    }
}

impl<M: StableMemory + Clone + Default> From<StableCanisterState> for SnsWasmCanister<M> {
    fn from(stable_canister_state: StableCanisterState) -> Self {
        let wasm_indexes: BTreeMap<[u8; 32], SnsWasmStableIndex> = stable_canister_state
            .wasm_indexes
            .into_iter()
            .map(|index| (vec_to_hash(index.hash.clone()).unwrap(), index))
            .collect();

        let stable_upgrade_path = stable_canister_state.upgrade_path.unwrap_or_default();

        let upgrade_path = stable_upgrade_path.into();

        let sns_subnet_ids = stable_canister_state
            .sns_subnet_ids
            .into_iter()
            .map(|id| id.into())
            .collect();

        SnsWasmCanister {
            wasm_indexes,
            sns_subnet_ids,
            deployed_sns_list: stable_canister_state.deployed_sns_list,
            upgrade_path,
            stable_memory: SnsWasmStableMemory::<M>::default(),
            access_controls_enabled: stable_canister_state.access_controls_enabled,
            allowed_principals: stable_canister_state.allowed_principals,
        }
    }
}

impl<M: StableMemory + Clone + Default> From<SnsWasmCanister<M>> for StableCanisterState {
    fn from(state: SnsWasmCanister<M>) -> StableCanisterState {
        let wasm_indexes = state.wasm_indexes.values().cloned().collect();
        let sns_subnet_ids = state
            .sns_subnet_ids
            .into_iter()
            .map(|id| id.get())
            .collect();
        let deployed_sns_list = state.deployed_sns_list;
        let upgrade_path = Some(state.upgrade_path.into());
        let access_controls_enabled = state.access_controls_enabled;
        let allowed_principals = state.allowed_principals;

        StableCanisterState {
            wasm_indexes,
            sns_subnet_ids,
            deployed_sns_list,
            upgrade_path,
            access_controls_enabled,
            allowed_principals,
        }
    }
}

impl From<UpgradePath> for StableUpgradePath {
    fn from(path: UpgradePath) -> Self {
        Self {
            latest_version: Some(path.latest_version),
            upgrade_path: path
                .upgrade_path
                .into_iter()
                .map(|(current, next)| SnsUpgrade {
                    current_version: Some(current),
                    next_version: Some(next),
                })
                .collect(),
        }
    }
}

impl From<StableUpgradePath> for UpgradePath {
    fn from(stable_upgrade_path: StableUpgradePath) -> Self {
        let upgrade_path_hashmap = stable_upgrade_path
            .upgrade_path
            .into_iter()
            .map(|upgrade| {
                (
                    upgrade.current_version.unwrap(),
                    upgrade.next_version.unwrap(),
                )
            })
            .collect();

        UpgradePath {
            latest_version: stable_upgrade_path.latest_version.unwrap_or_default(),
            upgrade_path: upgrade_path_hashmap,
        }
    }
}

impl SnsCanisterIds {
    /// Get a set of "Name, CanisterId" tuples, useful for repetitive operations that need
    /// per-canister error messages.  Does not return canisters without a principal.
    pub fn into_named_tuples(self) -> Vec<(String, CanisterId)> {
        vec![
            ("Root".to_string(), self.root),
            ("Governance".to_string(), self.governance),
            ("Ledger".to_string(), self.ledger),
            ("Swap".to_string(), self.swap),
            ("Index".to_string(), self.index),
        ]
        .into_iter()
        .flat_map(|(label, principal_id)| {
            principal_id.map(|principal_id| (label, CanisterId::new(principal_id).unwrap()))
        })
        .collect()
    }
}

impl FromStr for SnsCanisterType {
    type Err = ();

    fn from_str(input: &str) -> Result<SnsCanisterType, Self::Err> {
        match input {
            "Unspecified" => Ok(SnsCanisterType::Unspecified),
            "Root" => Ok(SnsCanisterType::Root),
            "Governance" => Ok(SnsCanisterType::Governance),
            "Ledger" => Ok(SnsCanisterType::Ledger),
            "Swap" => Ok(SnsCanisterType::Swap),
            "Archive" => Ok(SnsCanisterType::Archive),
            _ => Err(()),
        }
    }
}
