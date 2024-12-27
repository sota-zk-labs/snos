use std::collections::HashMap;
use std::io::Write;
use std::{fs, path};

use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use cairo_vm::Felt252;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::serde_as;
use starknet_api::deprecated_contract_class::ContractClass as DeprecatedContractClass;

use super::InternalTransaction;
use crate::config::StarknetGeneralConfig;
use crate::error::SnOsError;
use crate::starknet::business_logic::fact_state::contract_state_objects::ContractState;
use crate::starknet::starknet_storage::CommitmentInfo;
use crate::utils::Felt252HexNoPrefix;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StarknetOsInput {
    pub contract_state_commitment_info: CommitmentInfo,
    pub contract_class_commitment_info: CommitmentInfo,
    pub deprecated_compiled_classes: HashMap<Felt252, DeprecatedContractClass>,
    pub compiled_classes: HashMap<Felt252, CasmContractClass>,
    pub compiled_class_visited_pcs: HashMap<Felt252, Vec<Felt252>>,
    pub contracts: HashMap<Felt252, ContractState>,
    pub class_hash_to_compiled_class_hash: HashMap<Felt252, Felt252>,
    pub general_config: StarknetGeneralConfig,
    pub transactions: Vec<InternalTransaction>,
    pub block_hash: Felt252,
}

impl StarknetOsInput {
    pub fn load(path: &path::Path) -> Result<Self, SnOsError> {
        let raw_input = fs::read_to_string(path)?;
        let input = serde_json::from_str(&raw_input)?;

        Ok(input)
    }

    pub fn dump(&self, path: &path::Path) -> Result<(), SnOsError> {
        fs::File::create(path)?.write_all(&serde_json::to_vec(&self)?)?;

        Ok(())
    }

    // pub fn to_json_string(&self) -> String {
    //     let contract_state_commitment_info = json!({
    //         "previous_root": self.contract_state_commitment_info.previous_root.to_string(),
    //         "updated_root": self.contract_state_commitment_info.updated_root.to_string(),
    //         "tree_height": self.contract_state_commitment_info.tree_height,
    //         "commitment_facts": HashMap<Felt252, Vec<Felt252>>,
    //     });
    //     serde_json::to_string_pretty(json!({
    //         "contract_state_commitment_info": CommitmentInfo,
    //         "contract_class_commitment_info": CommitmentInfo,
    //         "deprecated_compiled_classes": HashMap<Felt252, DeprecatedContractClass>,
    //         "compiled_classes": HashMap<Felt252, CasmContractClass>,
    //         "compiled_class_visited_pcs": HashMap<Felt252, Vec<Felt252>>,
    //         "contracts": HashMap<Felt252, ContractState>,
    //         "class_hash_to_compiled_class_hash": HashMap<Felt252, Felt252>,
    //         "general_config": StarknetGeneralConfig,
    //         "transactions": Vec<InternalTransaction>,
    //         "block_hash": Felt252,
    //     })).unwrap()
    // }
}

#[serde_as]
#[derive(Deserialize, Clone, Default, Debug, Serialize, PartialEq)]
pub struct StorageCommitment {
    #[serde_as(as = "Felt252HexNoPrefix")]
    pub root: Felt252,
    pub height: usize,
}
