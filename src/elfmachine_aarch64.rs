// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Support for writing ELF files to an output; machine layer

use std::mem::size_of;

use anyhow::Context;
use libc::{user_fpsimd_struct, user_regs_struct, siginfo_t};
use libelf_sys::{Elf64_Half, EM_AARCH64, NT_SIGINFO, NT_PRFPREG, NT_PRSTATUS, NT_ARM_PAC_MASK};
use procfs::process::{Task, Process};

use crate::{write_elf::{ElfNote, ElfNoteSpec, NOTE_NAME_CORE, NOTE_NAME_LINUX}, ptrace::{ptrace_getsiginfo, ptrace_get_regset}, linux::{Prstatus, load_prstatus_for_task}, byte_helpers::prstatus_to_bytes};

pub const ELF_MACHINE_ID: Elf64_Half = EM_AARCH64 as Elf64_Half;

pub fn collect_per_task_note_specs(_process: &Process) -> Result<Vec<ElfNoteSpec>, Box<dyn std::error::Error>> {
    let mut specs = Vec::new();

    specs.push(ElfNoteSpec{size: size_of::<Prstatus>()});
    specs.push(ElfNoteSpec{size: size_of::<user_fpsimd_struct>()});
    specs.push(ElfNoteSpec{size: 16});
    specs.push(ElfNoteSpec{size: size_of::<siginfo_t>()});

    Ok(specs)
}

pub fn collect_task_notes(task: &Task) -> Result<Vec<ElfNote>, Box<dyn std::error::Error>> {
    let regs_mem = ptrace_get_regset(task, NT_PRSTATUS, size_of::<user_regs_struct>()).context("user_regs thread")?;
    let regs_mem_u = regs_mem.unwrap();
    let (_, regs, _) = unsafe { regs_mem_u.align_to::<user_regs_struct>() };
    let fpregs = ptrace_get_regset(task, NT_PRFPREG, size_of::<user_fpsimd_struct>()).context("fpsimd thread")?;
    let siginfo = ptrace_getsiginfo(&task);
    let prstatus = load_prstatus_for_task(task, regs[0]).context("load_prstatus_for_task")?;
    let pac_mask = ptrace_get_regset(task, NT_ARM_PAC_MASK, 16).context("ARM PAC mask thread")?;

    let mut notes = Vec::new();

    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_PRSTATUS,
            description: prstatus_to_bytes(&prstatus).to_vec(),
            friendly: "thread user_regs_struct",
        });

    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_PRFPREG,
            description: fpregs.unwrap(),
            friendly: "thread user_fpsimd_struct",
        });

    notes.push(ElfNote {
            note_name: NOTE_NAME_LINUX,
            note_type: NT_ARM_PAC_MASK,
            description: pac_mask.unwrap(),
            friendly: "thread user_fpsimd_struct",
        });

    notes.push(ElfNote {
            note_name: NOTE_NAME_CORE,
            note_type: NT_SIGINFO,
            description: siginfo,
            friendly: "thread siginfo",
        });

    Ok(notes)
}
