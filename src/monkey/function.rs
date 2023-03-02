use binaryninja::{binaryninjacore_sys::BNFunction, function::Function};


pub struct MonkeyFunction {
    pub(crate) handle: *mut BNFunction,
}


pub fn create_monkey_function(func: &Function) -> &MonkeyFunction
{
    let exposed: &MonkeyFunction = unsafe 
    {
        std::mem::transmute(func)
    };

    return exposed;
}