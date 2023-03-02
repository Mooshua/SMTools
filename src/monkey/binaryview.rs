use binaryninja::{binaryninjacore_sys::{BNArchitecture, BNBinaryView}, architecture::CoreArchitecture, binaryview::BinaryView};

#[derive(Debug, Copy, Clone)]
pub struct MonkeyBinaryView {
    pub handle: *mut BNBinaryView,
}

pub fn create_monkey_bv(func: &BinaryView) -> &MonkeyBinaryView
{
    let exposed: &MonkeyBinaryView = unsafe 
    {
        std::mem::transmute(func)
    };

    return exposed;
}
