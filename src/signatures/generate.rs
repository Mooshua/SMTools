use std::ops::{Deref, DerefMut};
use std::time::Instant;
use binaryninja::{binaryview::{BinaryView, BinaryViewExt}, function::Function, binaryninjacore_sys::{BNGetConstantsReferencedByInstructionIfAvailable, BNFreeConstantReferenceList}, interaction::show_message_box, rc};
use binaryninja::binaryview::BinaryViewBase;
use log::{warn, error, info};

use crate::{monkey::{function::*, arch::create_monkey_arch}, signatures::scan::find_signature};
use crate::signatures::linear_generate::linear_generate_signature;
use crate::utils::function::{find_address_base, find_func_end};

use super::sigbyte::SigByte;

pub fn consume_instruction<'a>(base: &Function, view: &BinaryView, offset: u64) -> Result<Vec<SigByte>, String> {
    let arch = base.arch();
    let arch_ref = arch.as_ref();
    let instruction_len = view.instruction_len(arch_ref, offset);

    match instruction_len {
        Some(size) => {
            if size == 0 {
                return Err("Invalid instruction size".to_string());
            }

            let bytes = view.read_vec(offset, size);

            let mut wildcard = 0;

            {
                let mFunc = create_monkey_function(base);
                let bnFunc = mFunc.handle;

                let mArch = create_monkey_arch(arch_ref);
                let bnArch = mArch.0;

                unsafe {
                    let mut size: usize = 0;
                    let constants = BNGetConstantsReferencedByInstructionIfAvailable(
                        bnFunc, bnArch, offset, &mut size,
                    );

                    for index in 0..size {
                        let constant_ptr = constants.add(index);
                        let constant = *constant_ptr;

                        //info!("Constant {0}: Size {1} Val {2} Ptr {3} Inter {4}", index, constant.size, constant.value, constant.pointer, constant.intermediate);

                        if (constant.pointer && constant.value != 0) {
                            wildcard += constant.size;
                        }
                    }

                    BNFreeConstantReferenceList(constants);
                }
            }

            let mut sig_bytes = vec![SigByte::Wildcard; size];

            if (wildcard >= size)
            {
                return Err(format!("Invalid instruction const parameters: Wildcard size is {0}, exceeding instruction size {1}.", wildcard, size));
            }

            for index in 0..(size - wildcard) {
                //  TODO: Remove this awfulness
                //sig_bytes.splice(index..index, vec![SigByte::Match(bytes[index])]);
                &sig_bytes.remove(index);
                &sig_bytes.insert(index, SigByte::Match(bytes[index]));
            }

            return Ok(sig_bytes);
        }
        None => {
            return Err(format!("Failure getting instruction length at {0}.", offset));
        }
    }
}




pub fn generate_and_print_signature(view: &BinaryView, offset: u64) {
    if (!view.offset_valid(offset)) {
        error!("[SMTools] Invalid Address");
    }

    let base = find_address_base(view, offset);

    match base {
        Ok(func) => {
            let delta = offset - func.start();

            let now = Instant::now();
            let sig = linear_generate_signature(view, offset, func.to_owned());
            info!("[SMTools] Linear scan completed in {0}ms", now.elapsed().as_millis());
            match sig
            {
                Ok(signature) => {

                    info!("[SMTools] Signature for '{0}' + ({1:#02x}/{1})", func.symbol().full_name(), delta);
                    info!("[SMTools] Generic: {0}", signature.to_owned().into_iter().map(|s| s.to_str_generic() ).collect::<String>());
                    info!("[SMTools] Sourcemod: {0}", signature.to_owned().into_iter().map(|s| s.to_str_sm() ).collect::<String>());
                }
                Err(reason) =>
                    {
                        warn!("[SMTools] Failed to get signature for '{0}' + ({1:#02x}/{1}): '{2}'", func.symbol().full_name(), delta, reason);
                    }
            }
            
        }
        Err(reason) => {
            error!("[SMTools] Failed to find base! {0}", reason);
        }
    }
}

pub fn generate_signature(
    view: &BinaryView,
    offset: u64,
    func: rc::Ref<Function>,
) -> Result<Vec<SigByte>, String> {
    let mut func_end = find_func_end(&func);

    let mut first =  consume_instruction(func.as_ref(), view, offset);
    if let Err(msg) = &first
    {
        return Err(msg.to_owned());
    }
    let mut signature: &mut Vec<SigByte> = &mut first.expect("Impossible error");

    let mut iter = 0;

    while find_signature(&signature, view, 2).len() == 2 {
        //  This crashes if we read the padding after a function
        //  So we have to ensure we stay within
        if
        /*func.highest_address()*/
        func_end <= (offset + (signature.len() as u64)) {
            warn!("[SMTools] HIT FUNC LIMIT");
            show_message_box("SMTools", "There was not enough unique bytes left in the function to create a signature.", binaryninja::binaryninjacore_sys::BNMessageBoxButtonSet::OKButtonSet, binaryninja::binaryninjacore_sys::BNMessageBoxIcon::WarningIcon);
            return Err("Not enough unique bytes in the remainder of the subroutine".to_string());
        }

        //info!("[SMTools] Length {0}", signature.len());
        //info!("[SMTools] Sig {:?}", signature);

        let pointer = offset + (signature.len() as u64);
        let mut instruction = consume_instruction(func.as_ref(), view, pointer);

        if let Err(msg) = instruction.as_ref()
        {
            return Err(msg.to_owned());
        }
        if let Ok(contribution) = instruction.as_ref() {
            signature.extend_from_slice(contribution.deref());
        }

        iter = iter + 1;

        if iter >= 25 {
            warn!("[SMTools] HIT ITER LIMIT");
            show_message_box("SMTools", "Hit scan iteration limit before finding a unique signature.", binaryninja::binaryninjacore_sys::BNMessageBoxButtonSet::OKButtonSet, binaryninja::binaryninjacore_sys::BNMessageBoxIcon::WarningIcon);
            return Err("Hit iteration limit".to_string());
        }
    }

    info!("[SMTools] Done! Length {0}", signature.len());
    info!("[SMTools] Final Sig {:?}", signature);

    return Ok(signature.to_owned());
}

