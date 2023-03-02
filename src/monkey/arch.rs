use binaryninja::{binaryninjacore_sys::BNArchitecture, architecture::CoreArchitecture};

pub struct MonkeyCoreArchitecture(pub *mut BNArchitecture);

pub fn create_monkey_arch(func: &CoreArchitecture) -> &MonkeyCoreArchitecture
{
    let exposed: &MonkeyCoreArchitecture = unsafe 
    {
        std::mem::transmute(func)
    };

    return exposed;
}