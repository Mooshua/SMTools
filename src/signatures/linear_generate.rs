
//  Linear generate:
//  Linearly iterate over memory to generate a signature in near O(n) time.

use std::io::{Read, Seek, SeekFrom};
use binaryninja::binaryreader::BinaryReader;
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::function::Function;
use binaryninja::interaction::show_message_box;
use binaryninja::rc;
use log::{error, info, warn};
use crate::SigByte;
use crate::signatures::generate::consume_instruction;
use crate::signatures::scan::sig_matches;
use crate::utils::function::{find_func_end, read_view};

pub fn linear_generate_signature(view: &BinaryView, sig_address: u64, func: rc::Ref<Function>) -> Result<Vec<SigByte>, String> {

    let buf = read_view(view);

    let mut sig: Vec<SigByte> = Vec::new();
    let mut func_end = find_func_end(&func);


    for address in 0..(buf.len() - (sig.len()) - 1) as u64 {

        let real_address = address + view.start();

        if real_address == sig_address
        {
            continue;
        }

        while sig_matches(&sig, buf.as_ref(), address) {

            if func_end <= (sig_address + (sig.len() as u64)) {
                warn!("[SMTools] HIT FUNC LIMIT");
                show_message_box("SMTools", "There was not enough unique bytes left in the function to create a signature.", binaryninja::binaryninjacore_sys::BNMessageBoxButtonSet::OKButtonSet, binaryninja::binaryninjacore_sys::BNMessageBoxIcon::WarningIcon);
                return Err("Not enough unique bytes in the remainder of the subroutine".to_string());
            }

            let pointer = sig_address + (sig.len() as u64);
            let mut instruction = consume_instruction(func.as_ref(), view, pointer);
            if let Err(msg) = &instruction
            {
                return Err(format!("Error scanning: {0}", msg));
            }
            sig.append(&mut instruction.expect("Impossible error"));

        }
    }
    //  Now, append a few instructions if we still have room
    //  Just to make the signature a little bit more resilient to collisions
    for addition in 0..3
    {
        if func_end <= (sig_address + (sig.len() as u64)) {
            warn!("[SMTools] Warning: Hit func end while hardening signature ({0}/4).", addition);
            warn!("[SMTools] Signature is still unique, but may be more likely to collide during updates.");
            break;
        }

        let pointer = sig_address + (sig.len() as u64);
        let mut instruction = consume_instruction(func.as_ref(), view, pointer);
        if let Err(msg) = &instruction
        {
            warn!("[SMTools] Warning: Error hardening signature ({0}/4): {1}", addition, msg);
            warn!("[SMTools] Signature is still unique, but may be more likely to collide during updates.");
            break;
        }
        sig.append(&mut instruction.expect("Impossible error"));
    }

    return Ok(sig);
}