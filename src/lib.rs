use std::{cell::Ref, ffi::c_void, fmt::Binary, thread, u8};

use binaryninja::{
    architecture::Architecture,
    binaryninjacore_sys::{
        BNFreeConstantReferenceList, BNGetConstantsReferencedByInstruction,
        BNGetConstantsReferencedByInstructionIfAvailable, BNWorkerEnqueue,
    },
    binaryview::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{register_for_address, AddressCommand},
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenContents},
    flowgraph::{BranchType, EdgePenStyle, EdgeStyle, FlowGraph, FlowGraphNode, ThemeColor},
    function::Function,
    interaction::{show_message_box, MessageBoxButtonSet, MessageBoxIcon},
    logger::init,
    rc,
    string::BnString,
};
use binaryninja::command::{Command, FunctionCommand, register, register_for_function};
use binaryninja::interaction::get_text_line_input;
use log::{debug, error, info, warn, LevelFilter};
use monkey::{
    arch::create_monkey_arch,
    binaryview::{create_monkey_bv},
    function::create_monkey_function,
};
use signatures::sigbyte::SigByte;
use crate::signatures::generate::generate_and_print_signature;
use crate::signatures::scan::find_signature;
use crate::signatures::sigbyte::parse_signature;
use crate::utils::function::find_address_base;

pub mod monkey;
pub mod signatures;
pub mod utils;




struct GenerateSignatureCommand;

impl AddressCommand for GenerateSignatureCommand {
    fn action(&self, view: &BinaryView, addr: u64) {
        generate_and_print_signature(view, addr);
    }

    fn valid(&self, view: &BinaryView, addr: u64) -> bool {
        // Your code here
        true
    }
}

struct GenerateFuncSignatureCommand;

impl FunctionCommand for GenerateFuncSignatureCommand {
    fn action(&self, view: &BinaryView, func: &Function) {
        generate_and_print_signature(view, func.start());
    }

    fn valid(&self, view: &BinaryView, func: &Function) -> bool {
        // Your code here
        true
    }
}

struct FindSignatureCommand;

impl Command for FindSignatureCommand {
    fn action(&self, view: &BinaryView) {
        let signature = get_text_line_input("Signature", "SMTools");
        match signature
        {
            Some(sig_str)   => {
                let parsed = parse_signature(sig_str);
                match parsed
                {
                    Ok(sig) => {
                        info!("[SMTools] Parsed signature! {0:?}", sig);
                        let matches = find_signature(&sig, view, 50);
                        info!("[SMTools] First 50 matches:");
                        for sig_match in matches.into_iter() {
                            let func_scan = find_address_base(view, sig_match);
                            match func_scan
                            {
                                Ok(func) => info!("[SMTools] Match at {0:#08X} ({1} @ {2:#08X})", sig_match, func.symbol().full_name(), func.start()),
                                Err(msg) => info!("[SMTools] Match at {0:#08X} (no func: {1})", sig_match, msg)
                            }

                        }
                    }
                    Err(msg) => {
                        warn!("[SMTools] Failed to parse signature: {0}", msg);
                    }
                }
            }
            None => {
                warn!("[SMTools] No signature provided");
            }
        }
    }
    fn valid(&self, view: &BinaryView) -> bool {
        true
    }
}

#[no_mangle]
pub extern "C" fn UIPluginInit() -> bool {
    binaryninja::logger::init(LevelFilter::Trace).expect("failed to initialize logging");
    register_for_address(
        "[SMT] Generate Signature (Address)",
        "Generate a signature beginning at this address",
        GenerateSignatureCommand {},
    );
    register_for_function("[SMT] Generate Signature (Function)", "Generate a signature beginning at the current function", GenerateFuncSignatureCommand {} );
    register("[SMT] Find Signature", "Find all matches of a signature", FindSignatureCommand {});
    true
}
