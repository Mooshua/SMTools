use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::function::Function;
use binaryninja::rc;
use binaryninja::rc::Ref;

pub fn find_address_base(view: &BinaryView, offset: u64) -> Result<rc::Ref<Function>, &str> {
    let blocks = view.basic_blocks_containing(offset);

    if blocks.len() > 1 {
        return Err("Multiple blocks contained within address");
    }

    if blocks.len() == 1 {
        return Ok(blocks.get(0).function());
    }

    return Err("Address is not within function");
}

pub fn find_func_end(func: &Function) -> u64
{
    let mut func_end = 0;
    for block in func.basic_blocks().into_iter() {
        func_end = func_end.max(block.raw_end());
    }
    return func_end;
}