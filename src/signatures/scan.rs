use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};

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
    let buf = view.read_vec(view.start(), view.len());

    let mut matches = Vec::new();

    for address in 0..(buf.len() - (signature.len()) - 1) as u64 {
        if (sig_matches(signature, buf.as_ref(), address)) {
            matches.push(address + view.start());

            if (matches.len() >= maxmatches) {
                //  Cut search short early
                return matches;
            }
        }
    }

    return matches;
}