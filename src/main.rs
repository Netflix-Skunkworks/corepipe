// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
#[macro_use]
extern crate scan_fmt;

mod bindings;
mod byte_helpers;
mod process_info;
mod process_memory;
mod ptrace;
mod smaps;
mod sysconf;
mod write_elf;

use crate::bindings::prpsinfo;
use crate::process_info::load_prstatus_for_task;
use crate::smaps::SmapRange;
use anyhow::Context;
use clap::Parser;
use log::{debug, info};
use nix::unistd::Pid;
use process_memory::ProcessMemory;
use procfs::process::Process;
use std::io;
use sysconf::load_sysconfs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The process ID (PID) to coredump
    #[arg(short, long)]
    pid: libc::pid_t,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    let args = Args::parse();
    let pid: libc::pid_t = args.pid;
    let output = &mut io::stdout();

    info!("dumping core for pid {} ...", pid);

    debug!("loading sysconf data...");
    load_sysconfs().context("Failed to load sysconf data")?;

    let nixpid = Pid::from_raw(pid);
    debug!("performing ptrace attach/sieze...");
    ptrace::ptrace_attach_all(nixpid).context("could not ptrace attach to all targets")?;

    info!("halted.");

    // from here on in we are collecting and then emitting data

    info!("collecting process data...");

    // collect data
    let smaps: Vec<SmapRange> =
        smaps::read_smaps(nixpid).context("could not parse /proc//smaps")?;
    let process = Process::new(pid)?;
    let auxv_table = process.auxv().context("error reading auxv table")?;
    let procfs_info = prpsinfo::try_from(&process).context("error building prpsinfo")?;
    let count_tasks = process
        .tasks()
        .context("failed counting process tasks")?
        .count();
    let general_register_size = ptrace::ptrace_get_regset_size(
        &process
            .task_main_thread()
            .context("failed to read task_main_thread for pid")?,
    )
    .context("should be able to read register state")?;

    info!("emitting ELF headers...");

    /*
     * this captures the core file structure at a high level
     * https://www.gabriel.urdhr.fr/2015/05/29/core-file
     */
    write_elf::write_elf_header(&smaps, output).context("should have written elf header")?;
    write_elf::write_program_header(
        &smaps,
        &auxv_table,
        count_tasks,
        general_register_size,
        output,
    )
    .context("should have written program header")?;
    write_elf::write_note_prpsinfo(procfs_info, output).context("should have written prpsinfo")?;

    for task in process
        .tasks()
        .context("failed reading process tasks")?
        .flatten()
    {
        debug!("writing headers for thread {}...", task.tid);

        let fp_registers = ptrace::ptrace_get_fpregset(&task)
            .context("should be able to read fpregset for thread")?;
        let general_registers =
            ptrace::ptrace_get_regset(&task).context("should be able to read regset for thread")?;
        let regs = ptrace::ptrace_getregs(Pid::from_raw(task.tid))
            .context("should have been able to read registers for thread")?;
        let prs = load_prstatus_for_task(&task, regs)
            .context("should have been able to read proc/stat and proc/status for thread")?;
        let siginfo = ptrace::ptrace_getsiginfo(&task);

        write_elf::write_note_prstatus(prs, output)
            .context("could not write note thread prstatus")?;
        write_elf::write_note_fpregset(fp_registers, output)
            .context("could not write thread fpregset")?;
        if let Some(regs) = general_registers {
            write_elf::write_note_regset(regs, output).context("could not write thread regset")?;
        }
        write_elf::write_note_siginfo(siginfo, output).context("could not write thread siginfo")?;
    }

    write_elf::write_note_auxv(auxv_table, output).context("could not write auxv notes")?;
    write_elf::write_note_mapped_files(&smaps, output)
        .context("could not write mapped files notes")?;

    info!("emitting ELF load contents...");

    let mut process_memory = ProcessMemory::new(pid).context("could not open process memory")?;
    write_elf::write_load_sections(&smaps, &mut process_memory, output)?;

    info!("dump complete.");

    // all done!
    Ok(())
}
