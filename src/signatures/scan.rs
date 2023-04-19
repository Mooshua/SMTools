use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::interaction::show_message_box;
use log::warn;
use crate::utils::function::read_view;

use super::sigbyte::SigByte;

pub fn sig_matches(signature: &Vec<SigByte>, buffer: &Vec<u8>, offset: u64) -> bool {
    if (offset >= (usize::MAX as u64)) {
        return false;
    }

    if (buffer.len() - (offset as usize) - 1) <= (signature.len()) {
        return false;
    }

    for index in 0..signature.len() {
        let mode = signature[index];
        let byte = buffer[index + (offset as usize)];

        let good = match mode {
            SigByte::Wildcard => true,
            SigByte::Match(value) => value == byte,
        };

        if !good {
            return false;
        }
    }

    return true;
}

pub fn find_signature(signature: &Vec<SigByte>, view: &BinaryView, maxmatches: usize) -> Vec<u64> {
    let buf = read_view(view);

    let mut matches = Vec::new();

    for address in 0..(buf.len() - (signature.len()) - 1) as u64 {
        let real_address = address + view.start();
        if (sig_matches(signature, buf.as_ref(), real_address)) {
            show_message_box("Match!", address.to_string(), Info)
            matches.push(real_address);

            if (matches.len() >= maxmatches) {
                //  Cut search short early
                return matches;
            }
        }
    }


    return matches;
}