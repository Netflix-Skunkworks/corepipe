// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
#[macro_use]
extern crate scan_fmt;

mod byte_helpers;
mod linux;
mod process_memory;
mod ptrace;
mod smaps;
mod sysconf;
mod write_elf;

#[cfg_attr(target_arch = "aarch64", path="elfmachine_aarch64.rs")]
#[cfg_attr(target_arch = "x86_64", path="elfmachine_x86_64.rs")]
mod elfmachine;

use crate::byte_helpers::prpsinfo_to_bytes;
use crate::linux::Prpsinfo;
use crate::elfmachine::collect_per_task_note_specs;
use crate::smaps::SmapRange;
use crate::write_elf::{ElfNote, NOTE_NAME_CORE};
use anyhow::Context;
use clap::Parser;
use libelf_sys::NT_PRPSINFO;
use log::{debug, info, trace};
use nix::unistd::Pid;
use process_memory::ProcessMemory;
use procfs::ProcError;
use procfs::process::Process;
use std::{io, cmp};
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
        .with_level(log::LevelFilter::Trace)
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
    let procfs_info = Prpsinfo::try_from(&process).context("error building prpsinfo")?;
    let count_tasks = process
        .tasks()
        .context("failed counting process tasks")?
        .count();
    let specs = collect_per_task_note_specs(&process)?;

    info!("emitting ELF headers...");

    /*
     * this captures the core file structure at a high level
     * https://www.gabriel.urdhr.fr/2015/05/29/core-file
     */
    write_elf::write_elf_header(&smaps, elfmachine::ELF_MACHINE_ID, output).context("should have written elf header")?;
    write_elf::write_program_header(
        &smaps,
        &auxv_table,
        count_tasks,
        specs,
        output,
    )
    .context("should have written program header")?;

    write_elf::write_note(
        &ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_PRPSINFO,
            description: prpsinfo_to_bytes(&procfs_info).to_vec(),
            friendly: "process prpsinfo",
        }, output)
        .context("should have written prpsinfo")?;

    for task in process
        .tasks()
        .context("failed reading process tasks")?
        .flatten()
    {
        let tid = task.tid;
        debug!("writing headers for thread {}...", tid);

        let notes = elfmachine::collect_task_notes(&task)?;

        for note in notes {
            let friendly = note.friendly;
            let ctx = format!("could not write {friendly} for {tid}");
            write_elf::write_note(&note, output).context(ctx)?;
        }
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

impl TryFrom<&Process> for Prpsinfo {
    /// Load prpsinfo struct information from /proc contents
    fn try_from(process: &Process) -> Result<Self, ProcError> {
        trace!("prpsinfo::try_from loading process {}", process.pid);

        let proc_stat = process.stat()?;
        let proc_status = process.status()?;

        let mut proc_stat_info = Prpsinfo {
            pr_pid: proc_stat.pid,
            pr_sname: proc_stat.state as libc::c_char,
            pr_ppid: proc_stat.ppid,
            pr_pgrp: proc_stat.pgrp,
            pr_sid: proc_stat.session,
            pr_flag: proc_stat.flags as u64,
            pr_nice: proc_stat.nice as i8,

            pr_uid: proc_status.ruid,
            pr_gid: proc_status.rgid,

            // we are going to mark it as running, because we forced a stop, which means the
            // state is always in trace stop so state will always be t (tracing stop)
            // we set it to running because .. what else can we do?
            pr_zomb: 0,
            pr_state: 0,

            pr_fname: [0; 16],
            pr_psargs: [0; 80],
        };

        let process_name = proc_status.name;

        let name_len = process_name.len();
        for (i, &byte) in process_name.as_bytes()[0..cmp::min(name_len, 15)]
            .iter()
            .enumerate()
        {
            proc_stat_info.pr_fname[i] = byte as libc::c_char;
        }

        for (i, &byte) in process_name.as_bytes()[0..cmp::min(name_len, 79)]
            .iter()
            .enumerate()
        {
            proc_stat_info.pr_psargs[i] = byte as libc::c_char;
        }

        Ok(proc_stat_info)
    }

    type Error = ProcError;
}
