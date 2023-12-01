// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Support for writing ELF files to an output; machine layer

use std::mem::size_of;

use anyhow::Context;
use libc::{user_fpsimd_struct, user_regs_struct, siginfo_t};
use libelf_sys::{Elf64_Half, EM_AARCH64, NT_SIGINFO, NT_PRFPREG, NT_PRSTATUS, NT_ARM_PAC_MASK};
use log::trace;
use procfs::process::{Task, Process};

use crate::{write_elf::{ElfNote, ElfNoteSpec, NOTE_NAME_CORE, NOTE_NAME_LINUX}, ptrace::{ptrace_getsiginfo, ptrace_get_regset}, linux::{Prstatus, load_prstatus_for_task}, byte_helpers::prstatus_to_bytes};

pub const ELF_MACHINE_ID: Elf64_Half = EM_AARCH64 as Elf64_Half;

pub fn collect_per_task_note_specs(process: &Process) -> Result<Vec<ElfNoteSpec>, Box<dyn std::error::Error>> {
    let main_thread = process
        .task_main_thread()
        .context("failed to read task_main_thread for pid")?;

    let pac_mask_result = ptrace_get_regset(&main_thread, NT_ARM_PAC_MASK, 16);

    let result = match pac_mask_result {
        Ok(_) => {
            vec![
                ElfNoteSpec{size: size_of::<Prstatus>()},
                ElfNoteSpec{size: size_of::<user_fpsimd_struct>()},
                ElfNoteSpec{size: 16},   // pac mask
                ElfNoteSpec{size: size_of::<siginfo_t>()},
            ]
        },
        Err(_) => {
            trace!("pac mask area not available");
            vec![
                ElfNoteSpec{size: size_of::<Prstatus>()},
                ElfNoteSpec{size: size_of::<user_fpsimd_struct>()},
                ElfNoteSpec{size: size_of::<siginfo_t>()},
            ]
        },
    };

    Ok(result)
}

pub fn collect_task_notes(task: &Task) -> Result<Vec<ElfNote>, Box<dyn std::error::Error>> {
    let regs_mem = ptrace_get_regset(task, NT_PRSTATUS, size_of::<user_regs_struct>())
        .context("user_regs thread")?;
    let regs_mem_u = regs_mem.unwrap();
    let (_, regs, _) = unsafe { regs_mem_u.align_to::<user_regs_struct>() };

    let fpregs = ptrace_get_regset(task, NT_PRFPREG, size_of::<user_fpsimd_struct>())
        .context("fpsimd thread")?.unwrap();

    let siginfo = ptrace_getsiginfo(task);

    let prstatus = load_prstatus_for_task(task, regs[0])
        .context("load_prstatus_for_task")?;
    let prstatus_v = prstatus_to_bytes(&prstatus).to_vec();

    let pac_mask_result = ptrace_get_regset(task, NT_ARM_PAC_MASK, 16);

    let mut result = vec![];

    result.push(ElfNote {
        note_name: NOTE_NAME_CORE,
        note_type: NT_PRSTATUS,
        description: prstatus_v,
        friendly: "thread user_regs_struct",
    });
    result.push(ElfNote {
        note_name: NOTE_NAME_CORE,
        note_type: NT_PRFPREG,
        description: fpregs,
        friendly: "thread user_fpsimd_struct",
    });

    match pac_mask_result {
        Ok(Some(pac_mask)) => {
            result.push(ElfNote {
                note_name: NOTE_NAME_LINUX,
                note_type: NT_ARM_PAC_MASK,
                description: pac_mask,
                friendly: "thread user_fpsimd_struct",
            });
        },
        _ => {},
    }

    result.push(ElfNote {
        note_name: NOTE_NAME_CORE,
        note_type: NT_SIGINFO,
        description: siginfo,
        friendly: "thread siginfo",
    });

    Ok(result)
}
