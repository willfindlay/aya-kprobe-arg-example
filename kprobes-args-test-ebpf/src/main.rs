#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    helpers,
    macros::{kprobe, map},
    maps::{HashMap, PerCpuArray},
    programs::ProbeContext,
};
use core::mem;
use vmlinux::task_struct;

#[map]
static mut SCHEDULED: HashMap<i32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static mut SCRATCH: PerCpuArray<task_struct> = PerCpuArray::with_max_entries(1, 0);

#[kprobe(name = "kprobes_args_test")]
pub fn kprobes_args_test(ctx: ProbeContext) -> u32 {
    match unsafe { try_kprobes_args_test(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_kprobes_args_test(ctx: ProbeContext) -> Result<u32, u32> {
    let tp: *const task_struct = match ctx.arg(0) {
        Some(tp) => tp,
        None => return Err(1),
    };

    let scratch_p = match SCRATCH.get_mut(0u32) {
        Some(v) => v,
        None => return Err(2),
    };

    helpers::gen::bpf_probe_read(
        scratch_p as *mut _ as *mut _,
        mem::size_of::<task_struct>() as u32,
        tp as *const _,
    );

    let scheduled = match SCHEDULED.get(&scratch_p.pid) {
        Some(v) => v,
        None => &0,
    };
    let scheduled = *scheduled + 1;
    let _ = SCHEDULED.insert(&scratch_p.pid, &scheduled, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
