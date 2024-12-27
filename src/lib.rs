use std::collections::HashMap;
use std::fs;

use blockifier::context::BlockContext;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::Felt252;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use serde_json::{json, Value};
use error::SnOsError;
use execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use execution::helper::ExecutionHelperWrapper;
use io::output::StarknetOsOutput;

use crate::execution::syscall_handler::OsSyscallHandlerWrapper;
use crate::hints::types::{PatriciaSkipValidationRunner, PatriciaTreeMode};
use crate::hints::vars;
use crate::io::input::StarknetOsInput;
use crate::starkware_utils::commitment_tree::base_types::TreeIndex;

mod cairo_types;
pub mod config;
pub mod crypto;
pub mod error;
pub mod execution;
pub mod hints;
pub mod io;
pub mod sharp;
pub mod starknet;
pub mod starkware_utils;
pub mod storage;
pub mod utils;

pub fn run_os(
    os_path: String,
    layout: LayoutName,
    os_input: StarknetOsInput,
    block_context: BlockContext,
    mut execution_helper: ExecutionHelperWrapper,
) -> Result<(CairoPie, StarknetOsOutput), SnOsError> {
    fs::write("os_input.json", serde_json::to_string_pretty(&os_input).unwrap()).unwrap();
    fs::write("block_context.json", serde_json::to_string_pretty(&block_context).unwrap()).unwrap();
    let ex = execution_helper.execution_helper.clone();
    let mut ex = ex.try_read().unwrap();
    fs::write("tx_execution_infos.json", serde_json::to_string_pretty(&ex.tx_execution_info_iter.as_slice()).unwrap()).unwrap();

    let mut storage_by_address: HashMap<Felt252, Value> = HashMap::new();
    for (k, v) in ex.storage_by_address.clone() {
        let mut storage = HashMap::new();
        for (a, b) in &v.ffc.storage.try_lock().unwrap().clone().db {
            storage.insert(hex::encode(a), hex::encode(b));
        }
        let previous_tree = json!({
            "height": v.previous_tree.height,
            "root": hex::encode(v.previous_tree.root.0),
        });
        storage_by_address.insert(k, json!({
            "previous_tree": previous_tree,
            "expected_updated_root": v.expected_updated_root.to_string(),
            "ongoing_storage_changes": v.ongoing_storage_changes,
            "ffc": {
                "storage": storage
            },
        }));
    }
    fs::write("storage_by_address.json", serde_json::to_string_pretty(&storage_by_address).unwrap()).unwrap();

    fs::write("old_block_number_and_hash.json", serde_json::to_string_pretty(&ex.old_block_number_and_hash).unwrap()).unwrap();
    // fs::write("tx_execution_infos.json", serde_json::to_string_pretty(&ex.tx_execution_info_iter.as_slice()).unwrap()).unwrap();

    // Init CairoRunConfig
    let cairo_run_config = CairoRunConfig { layout, relocate_mem: true, trace_enabled: true, ..Default::default() };
    let allow_missing_builtins = cairo_run_config.allow_missing_builtins.unwrap_or(false);

    // Load the Starknet OS Program
    let starknet_os = fs::read(os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
    let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init cairo runner
    let mut cairo_runner = CairoRunner::new(
        &program,
        cairo_run_config.layout,
        cairo_run_config.proof_mode,
        cairo_run_config.trace_enabled,
    )
    .map_err(|e| SnOsError::Runner(e.into()))?;

    // Init the Cairo VM
    let end = cairo_runner.initialize(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;

    // Setup Depsyscall Handler
    let deprecated_syscall_handler = DeprecatedOsSyscallHandlerWrapper::new(
        execution_helper.clone(),
        cairo_runner.vm.add_memory_segment(),
        block_context.block_info().clone(),
    );

    let syscall_handler = OsSyscallHandlerWrapper::new(execution_helper.clone());

    // Setup Globals
    cairo_runner.exec_scopes.insert_value(vars::scopes::OS_INPUT, os_input);
    cairo_runner.exec_scopes.insert_box(vars::scopes::BLOCK_CONTEXT, Box::new(block_context));
    cairo_runner.exec_scopes.insert_value(vars::scopes::EXECUTION_HELPER, execution_helper);
    cairo_runner.exec_scopes.insert_value(vars::scopes::DEPRECATED_SYSCALL_HANDLER, deprecated_syscall_handler);
    cairo_runner.exec_scopes.insert_value(vars::scopes::SYSCALL_HANDLER, syscall_handler);
    cairo_runner
        .exec_scopes
        .insert_value(vars::scopes::PATRICIA_SKIP_VALIDATION_RUNNER, None::<PatriciaSkipValidationRunner>);
    cairo_runner.exec_scopes.insert_value(vars::scopes::PATRICIA_TREE_MODE, PatriciaTreeMode::State);

    // Run the Cairo VM
    let mut sn_hint_processor = hints::SnosHintProcessor::default();
    cairo_runner
        .run_until_pc(end, &mut sn_hint_processor)
        .map_err(|err| VmException::from_vm_error(&cairo_runner, err))
        .map_err(|e| SnOsError::Runner(e.into()))?;

    // End the Cairo VM run
    cairo_runner
        .end_run(cairo_run_config.disable_trace_padding, false, &mut sn_hint_processor)
        .map_err(|e| SnOsError::Runner(e.into()))?;

    if cairo_run_config.proof_mode {
        cairo_runner.finalize_segments().map_err(|e| SnOsError::Runner(e.into()))?;
    }

    // Prepare and check expected output.
    let os_output = StarknetOsOutput::from_run(&cairo_runner.vm)?;

    cairo_runner.vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.read_return_values(allow_missing_builtins).map_err(|e| SnOsError::Runner(e.into()))?;
    cairo_runner.relocate(cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

    // Parse the Cairo VM output
    let pie = cairo_runner.get_cairo_pie().map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

    pie.write_zip_file("cairo_pie.zip".as_ref())?;
    fs::write("os_output.json", serde_json::to_string_pretty(&os_output).unwrap()).unwrap();
    Ok((pie, os_output))
}
