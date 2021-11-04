#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    helpers::bpf_probe_read,
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use vmlinux::task_struct;

#[map]
static mut SCHEDULED: HashMap<i32, u64> = HashMap::with_max_entries(10240, 0);

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

    let pid = bpf_probe_read(&(*tp).pid as *const vmlinux::pid_t).map_err(|_| 1u32)?;

    let scheduled = match SCHEDULED.get(&pid) {
        Some(v) => v,
        None => &0,
    };
    let scheduled = *scheduled + 1;
    let _ = SCHEDULED.insert(&pid, &scheduled, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
