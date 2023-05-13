// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Support for reading process information from `/proc`.

use std::cmp;

use libc::user_regs_struct;
use log::trace;
use nix::unistd::Pid;
use procfs::{
    process::{Process, Task},
    ProcError,
};

use crate::ptrace;
use crate::{
    bindings::{elf_timeval, i386_regs, prpsinfo, prstatus},
    sysconf,
};

/// Convert a u64 clocks as provided by /proc/ contents to an elf_timeval
fn to_elf_timeval(clocks: u64) -> elf_timeval {
    const MICROS_PER_SEC: u64 = 1_000_000;
    let clk_tck = sysconf::sc_clk_tck();

    elf_timeval {
        tv_sec: (clocks / clk_tck) as i64,
        tv_usec: (((clocks * MICROS_PER_SEC) / clk_tck) % MICROS_PER_SEC) as i64,
    }
}

/// Load prstatus struct information from /proc and ptrace contents
pub fn load_prstatus_for_task(task: &Task, regs: user_regs_struct) -> Result<prstatus, ProcError> {
    let tid = Pid::from_raw(task.tid);
    trace!("load_prstatus_for_task {}", task.tid);

    let elf_siginfo = ptrace::ptrace_getsiginfo_or_zeros(tid);
    let proc_stat = task.stat()?;
    let proc_status = task.status()?;

    Ok(prstatus {
        pr_pid: proc_stat.pid,
        pr_ppid: proc_stat.ppid,
        pr_pgrp: proc_stat.pgrp,
        pr_sid: proc_stat.session,
        pr_sigpend: proc_status.sigpnd,
        pr_sighold: proc_status.sigblk,

        pr_utime: to_elf_timeval(proc_stat.utime),
        pr_stime: to_elf_timeval(proc_stat.stime),
        pr_cutime: to_elf_timeval(proc_stat.cutime as u64),
        pr_cstime: to_elf_timeval(proc_stat.cstime as u64),

        pr_cursig: elf_siginfo.si_signo as u32,
        pr_fpvalid: 0,
        pr_info: elf_siginfo,
        pr_reg: i386_regs {
            r15: regs.r15,
            r14: regs.r14,
            r13: regs.r13,
            r12: regs.r12,
            rbp: regs.rbp,
            rbx: regs.rbx,
            r11: regs.r11,
            r10: regs.r10,
            r9: regs.r9,
            r8: regs.r8,
            rax: regs.rax,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            orig_rax: regs.orig_rax,
            rip: regs.rip,
            cs: regs.cs,
            eflags: regs.eflags,
            rsp: regs.rsp,
            ss: regs.ss,
            fs_base: regs.fs_base,
            gs_base: regs.gs_base,
            ds: regs.ds,
            es: regs.es,
            fs: regs.fs,
            gs: regs.gs,
        },
    })
}

impl TryFrom<&Process> for prpsinfo {
    /// Load prpsinfo struct information from /proc contents
    fn try_from(process: &Process) -> Result<Self, ProcError> {
        trace!("prpsinfo::try_from loading process {}", process.pid);

        let proc_stat = process.stat()?;
        let proc_status = process.status()?;

        let mut proc_stat_info = prpsinfo {
            pr_pid: proc_stat.pid,
            pr_sname: proc_stat.state as i8,
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
            proc_stat_info.pr_fname[i] = byte as i8;
        }

        for (i, &byte) in process_name.as_bytes()[0..cmp::min(name_len, 79)]
            .iter()
            .enumerate()
        {
            proc_stat_info.pr_psargs[i] = byte as i8;
        }

        Ok(proc_stat_info)
    }

    type Error = ProcError;
}
