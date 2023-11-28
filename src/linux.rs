// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.

// ported the following BSD-3-Clause code across

/* Copyright (c) 2005-2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 * Author: Markus Gutschke, Carl Crous
 */

/*
 * Structs coming across from google-coredumper project.
 *
 * There is no formal documentation for the core file data structure, it is
 * only verifiable by comparing to output from gdb.
 *
 * https://github.com/madscientist/google-coredumper/tree/master/src
 * https://github.com/madscientist/google-coredumper/blob/master/src/elfcore.c
 */

use libc::user_regs_struct;
use log::trace;
use nix::unistd::Pid;
use procfs::{ProcError, process::Task};

use crate::sysconf;

// typedef struct elf_siginfo {    /* Information about signal (unused)         */                                                                                                            
//   int32_t si_signo;             /* Signal number                             */
//   int32_t si_code;              /* Extra code                                */
//   int32_t si_errno;             /* Errno                                     */
// } elf_siginfo;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ElfSiginfo {
    pub si_signo: i32,
    pub si_code: i32,
    pub si_errno: i32,
}

// typedef struct elf_timeval {    /* Time value with microsecond resolution    */
//   long tv_sec;                  /* Seconds                                   */
//   long tv_usec;                 /* Microseconds                              */
// } elf_timeval;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ElfTimeval {
    pub tv_sec: libc::c_long,
    pub tv_usec: libc::c_long,
}

// typedef struct prpsinfo {       /* Information about process                 */
//   unsigned char  pr_state;      /* Numeric process state                     */
//   char           pr_sname;      /* Char for pr_state                         */
//   unsigned char  pr_zomb;       /* Zombie                                    */
//   signed char    pr_nice;       /* Nice val                                  */
//   unsigned long  pr_flag;       /* Flags                                     */
//   uint32_t       pr_uid;        /* User ID                                   */
//   uint32_t       pr_gid;        /* Group ID                                  */
//   pid_t          pr_pid;        /* Process ID                                */
//   pid_t          pr_ppid;       /* Parent's process ID                       */
//   pid_t          pr_pgrp;       /* Group ID                                  */
//   pid_t          pr_sid;        /* Session ID                                */
//   char           pr_fname[16];  /* Filename of executable                    */
//   char           pr_psargs[80]; /* Initial part of arg list                  */
// } prpsinfo;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Prpsinfo {
    pub pr_state: libc::c_uchar,     // Numeric process state
    pub pr_sname: libc::c_char,      // Char for pr_state
    pub pr_zomb: libc::c_uchar,      // Zombie
    pub pr_nice: libc::c_schar,      // Nice val
    pub pr_flag: libc::c_ulong,      // Flags
    pub pr_uid: u32,      // User ID
    pub pr_gid: u32,      // Group ID
    pub pr_pid: libc::pid_t,         // Process ID
    pub pr_ppid: libc::pid_t,        // Parent's process ID
    pub pr_pgrp: libc::pid_t,        // Group ID
    pub pr_sid: libc::pid_t,         // Session ID
    pub pr_fname: [libc::c_char; 16],// Filename of executable
    pub pr_psargs: [libc::c_char; 80],// Initial part of arg list
}

// typedef struct i386_regs {    /* Normal (non-FPU) CPU registers            */
//   #define BP rbp
//   #define SP rsp
//   #define IP rip
//   uint64_t  r15,r14,r13,r12,rbp,rbx,r11,r10;
//   uint64_t  r9,r8,rax,rcx,rdx,rsi,rdi,orig_rax;
//   uint64_t  rip,cs,eflags;
//   uint64_t  rsp,ss;
//   uint64_t  fs_base, gs_base;
//   uint64_t  ds,es,fs,gs;
// } i386_regs;
// skip this and rely on libc::user_regs_struct

// typedef struct prstatus {       /* Information about thread; includes CPU reg*/
//   elf_siginfo    pr_info;       /* Info associated with signal               */
//   uint32_t       pr_cursig;     /* Current signal                            */
//   unsigned long  pr_sigpend;    /* Set of pending signals                    */
//   unsigned long  pr_sighold;    /* Set of held signals                       */
//   pid_t          pr_pid;        /* Process ID                                */
//   pid_t          pr_ppid;       /* Parent's process ID                       */
//   pid_t          pr_pgrp;       /* Group ID                                  */
//   pid_t          pr_sid;        /* Session ID                                */
//   elf_timeval    pr_utime;      /* User time                                 */
//   elf_timeval    pr_stime;      /* System time                               */
//   elf_timeval    pr_cutime;     /* Cumulative user time                      */
//   elf_timeval    pr_cstime;     /* Cumulative system time                    */
//   regs           pr_reg;        /* CPU registers                             */
//   uint32_t       pr_fpvalid;    /* True if math co-processor being used      */
// } prstatus;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Prstatus {
    pub pr_info: ElfSiginfo,
    pub pr_cursig: u32,
    pub pr_sigpend: libc::c_ulong,
    pub pr_sighold: libc::c_ulong,
    pub pr_pid: libc::pid_t,
    pub pr_ppid: libc::pid_t,
    pub pr_pgrp: libc::pid_t,
    pub pr_sid: libc::pid_t,
    pub pr_utime: ElfTimeval,
    pub pr_stime: ElfTimeval,
    pub pr_cutime: ElfTimeval,
    pub pr_cstime: ElfTimeval,
    pub pr_reg: user_regs_struct,
    pub pr_fpvalid: u32,
}

/// Convert a u64 clocks as provided by /proc/ contents to an elf_timeval
pub fn to_elf_timeval(clocks: u64) -> ElfTimeval {
    const MICROS_PER_SEC: u64 = 1_000_000;
    let clk_tck = sysconf::sc_clk_tck();

    ElfTimeval {
        tv_sec: (clocks / clk_tck) as i64,
        tv_usec: (((clocks * MICROS_PER_SEC) / clk_tck) % MICROS_PER_SEC) as i64,
    }
}

/// Load prstatus struct information from /proc and ptrace contents
pub fn load_prstatus_for_task(task: &Task, regs: user_regs_struct) -> Result<Prstatus, ProcError> {
    let tid = Pid::from_raw(task.tid);
    trace!("load_prstatus_for_task {}", task.tid);

    let elf_siginfo = crate::ptrace::ptrace_getsiginfo_or_zeros(tid);
    let proc_stat = task.stat()?;
    let proc_status = task.status()?;

    Ok(Prstatus {
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
        pr_reg: regs.clone(),
    })
}
