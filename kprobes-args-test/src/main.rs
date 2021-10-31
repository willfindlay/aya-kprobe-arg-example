use aya::maps::HashMap;
use aya::programs::KProbe;
use aya::Bpf;
use std::{
    convert::TryInto,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};
use structopt::StructOpt;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
}

fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;
    let program: &mut KProbe = bpf.program_mut("kprobes_args_test")?.try_into()?;
    program.load()?;
    program.attach("try_to_wake_up", 0)?;

    let scheduled: HashMap<_, i32, i64> = bpf.map_mut("SCHEDULED")?.try_into()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }

    for (pid, count) in unsafe { scheduled.iter() }.filter_map(Result::ok) {
        println!("pid {} is scheduled {} times", pid, count)
    }

    println!("Exiting...");

    Ok(())
}
