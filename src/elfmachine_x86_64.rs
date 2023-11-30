// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Support for writing ELF files to an output; machine layer

use std::mem::size_of;

use anyhow::Context;
use libelf_sys::{Elf64_Half, EM_X86_64, NT_PRSTATUS, NT_FPREGSET, NT_SIGINFO, NT_X86_XSTATE, NT_PRFPREG};
use log::trace;
use procfs::process::{Task, Process};
use crate::{byte_helpers::prstatus_to_bytes, write_elf::{ElfNoteSpec, NOTE_NAME_CORE}, linux::{Prstatus, load_prstatus_for_task}, ptrace::{ptrace_getsiginfo, ptrace_get_regset}};
use libc::{user_regs_struct, user_fpregs_struct};

use crate::write_elf::ElfNote;

pub const ELF_MACHINE_ID: Elf64_Half = EM_X86_64 as Elf64_Half;

pub fn collect_per_task_note_specs(process: &Process) -> Result<Vec<ElfNoteSpec>, Box<dyn std::error::Error>> {
    let mut specs = Vec::new();

    let main_thread = process
        .task_main_thread()
        .context("failed to read task_main_thread for pid")?;

    let xsave_register_size = get_xsave_area_size(&main_thread);

    specs.push(ElfNoteSpec{size: size_of::<Prstatus>()});
    specs.push(ElfNoteSpec{size: size_of::<user_fpregs_struct>()});

    if let Some(s) = xsave_register_size {
        specs.push(ElfNoteSpec{size: s});
    } 

    specs.push(ElfNoteSpec{size: size_of::<libc::siginfo_t>()});

    Ok(specs)
}

pub fn collect_task_notes(task: &Task) -> Result<Vec<ElfNote>, Box<dyn std::error::Error>> {
    let fp_registers = ptrace_get_regset(&task, NT_PRFPREG, size_of::<user_fpregs_struct>())
        .context("should be able to read fpregset for thread")?.unwrap();

    let x86_state_size = get_xsave_area_size(task).unwrap();
    let xsave_registers = ptrace_get_regset(&task, NT_X86_XSTATE, x86_state_size)
        .context("should be able to read xsave registers for thread")?;

    let regs_mem = ptrace_get_regset(&task, NT_PRSTATUS, size_of::<user_regs_struct>())
        .context("should be able to read normal registers for thread")?;
    let regs_mem_u = regs_mem.unwrap();
    let (_, regs, _) = unsafe { regs_mem_u.align_to::<user_regs_struct>() };

    let prs = load_prstatus_for_task(&task, regs[0])
        .context("should have been able to read proc/stat and proc/status for thread")?;
    let prstatus_v = prstatus_to_bytes(&prs).to_vec();

    let siginfo = ptrace_getsiginfo(&task);

    let mut notes = Vec::new();
    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_PRSTATUS,
            description: prstatus_v,
            friendly: "thread prstatus",
        });

    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_FPREGSET,
            description: fp_registers,
            friendly: "thread fpregset",
        });

    if let Some(regs) = xsave_registers {
        notes.push(ElfNote {
                note_name: crate::write_elf::NOTE_NAME_LINUX,
                note_type: libelf_sys::NT_X86_XSTATE,
                description: regs,
                friendly: "thread regset",
            });
    }

    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_SIGINFO,
            description: siginfo,
            friendly: "thread siginfo",
        });

    Ok(notes)
}

fn get_xsave_area_size(task: &Task) -> Option<usize> {
    use once_cell::sync::Lazy;
    use raw_cpuid::CpuId;

    let xsave_size = Lazy::new(|| {
        trace!("ptrace_get_regset_size x86_64 for task: {} (will be cached)", task.tid);

        let cpuid = CpuId::new();
        Some(cpuid.get_extended_state_info().map(|f| f.xsave_area_size_enabled_features()).unwrap() as usize)
    });

    *xsave_size
}
