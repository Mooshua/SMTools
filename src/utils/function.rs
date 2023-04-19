use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::function::Function;
use binaryninja::rc;
use binaryninja::rc::Ref;
use log::{debug, error};

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

pub fn read_view(view: &BinaryView) -> Vec<u8>
{
    let mut buf = Vec::new();
    let start = view.start();

    {
        let mut i = 0;
        let mut next = view.start();

        loop {

            i += 1;
            if i >= 1000 {
                error!("[SMTools] More than 1000 segments, quitting read");
                break;
            }

            let mut thislength = 0;

            while view.offset_readable(next + thislength) { thislength += 1 }

            let mut thisbuf = view.read_vec(next, (thislength as usize));

            let current = next + (thisbuf.len() as u64);

            buf.append(&mut thisbuf);

            next = view.next_valid_offset_after(current);
            let difference = next - current;
            debug!("[SMTools] [BufRead] Buf len: {0}, Len: {1}, Start: {2}, Next: {3}, Current: {4}", buf.len(), view.len(), start, next, current);

            if (next >= (start + (view.len() as u64)))
            {
                break;
            }

            for _ in 0..difference {
                buf.push(0);
            }
            debug!("[SMTools] [BufRead] AfterPad: {0}", buf.len())
        }
    }

    return buf;
}