/// Machine code for a function returning `10`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const RET10: &[u8] = &[0xB8, 0x0A, 0x00, 0x00, 0x00, 0xC3]; // mov eax, 10; ret
#[cfg(target_arch = "aarch64")]
const RET10: &[u8] = &[0x40, 0x01, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]; // mov w0, #10; ret

/// Creates a function returning `10`, located at least `distance` bytes after
/// `near` (i.e. beyond the reach of a relative branch).
pub fn far_ret10(near: usize, distance: usize) -> usize {
    let size = region::page::size();
    let mut hint = (near + distance).next_multiple_of(0x10000);

    for _ in 0..4096 {
        if let Some(address) = map_code(hint, size)
            && address.abs_diff(near) >= distance
        {
            return address;
        }
        hint += 0x10_0000;
    }

    panic!("could not map a distant function");
}

fn map_code(hint: usize, size: usize) -> Option<usize> {
    let mut memory = region::alloc_at(
        hint as *const u8,
        size,
        region::Protection::READ_WRITE_EXECUTE,
    )
    .ok()?;
    let address = memory.as_mut_ptr::<u8>();
    // SAFETY: The allocation is writable and large enough.
    unsafe { std::ptr::copy_nonoverlapping(RET10.as_ptr(), address, RET10.len()) };
    std::mem::forget(memory);
    crate::detour::memory::flush_instruction_cache(address, RET10.len());
    Some(address as usize)
}
