// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Wrappers for ptrace calls
//!
//! Simplifies a little of the work and makes it consistent across the various ptrace apis
//! available in rust rates.

use std::{io, mem::size_of};

use libc::{c_long, user_regs_struct, PTRACE_GETREGSET, user_fpregs_struct};
#[cfg(target_arch = "x86_64")]
use libelf_sys::NT_X86_XSTATE;
use log::{debug, trace, warn};
use nix::{
    errno::{self, errno, Errno},
    sys::{
        ptrace,
        signal::{kill, Signal},
        wait::waitpid,
    },
    unistd::Pid,
};
use procfs::process::{Process, Task};
use thiserror::Error;

use crate::{
    bindings::{elf_siginfo},
    byte_helpers::siginfo_to_bytes,
};

#[cfg(target_arch = "x86_64")]
use crate::bindings::X86_XSTATE_MAX_SIZE;

#[derive(Error, Debug)]
pub enum PtraceError {
    #[error("unable to perform nix syscall")]
    Errno(#[from] errno::Errno),

    #[error("not matching pid returned from waitpid() call")]
    WaitpidMismatch,

    #[error("not able to find process and tasks for process")]
    ProcessFindError(#[from] procfs::ProcError),
}

/// Ptrace attach to a given target process
///
/// This attaches to a given target process via the ptrace() framework. It
/// attaches to all child threads.
///
/// It sends a SIGCONT to allow automatic OS-provided detach and resume of
/// the target when this coredump debugger process exits (normally or
/// otherwise).
pub fn ptrace_attach_all(pid: Pid) -> Result<(), PtraceError> {
    // attach to main threads
    debug!("ptrace_attach_all attaching to pid {}", pid);
    ptrace::attach(pid)?;

    // wait for the process to stop
    debug!("ptrace_attach_all waiting for pid {}", pid);
    let wait_status = waitpid(pid, None)?;
    if wait_status.pid() != Some(pid) {
        return Err(PtraceError::WaitpidMismatch);
    }

    debug!("ptrace_attach_all seizing tasks");
    // also need to attach to all tasks in the process to read register contents
    for tid in Process::new(pid.as_raw())?
        .tasks()?
        .flatten()
        .filter(|task| task.tid != pid.as_raw())
        .map(|task| Pid::from_raw(task.tid))
    {
        trace!("ptrace_attach_all siezing task {}", tid);
        ptrace::seize(tid, ptrace::Options::empty())?;
    }

    // and, send a continue, to ensure that the target continues after we exit
    kill(pid, Signal::SIGCONT)?;

    debug!("ptrace_attach_all done");
    Ok(())
}

/// Read the user registers from the target thread id
pub fn ptrace_getregs(tid: Pid) -> Result<user_regs_struct, Errno> {
    trace!("ptrace_getregs for tid: {}", tid);
    ptrace::getregs(tid)
}

/// Load fpregset register information from ptrace
pub fn ptrace_get_fpregset(task: &Task) -> Result<Vec<u8>, Errno> {
    trace!("ptrace_get_fpregset for tid: {}", task.tid);
    const FPREGS_SIZE: usize = size_of::<user_fpregs_struct>();
    let mut fpregs: [u8; FPREGS_SIZE] = [0; FPREGS_SIZE];
    let mut data = io::IoSliceMut::new(&mut fpregs);

    // until this is supported, in nix, we do it natively
    // https://github.com/nix-rust/nix/pull/1844/files
    let ptrace_res: c_long =
        unsafe { libc::ptrace(libc::PTRACE_GETFPREGS, task.tid, 0, data.as_mut_ptr()) };
    let e: i32 = errno();

    if ptrace_res != -1 {
        Ok(fpregs.to_vec())
    } else {
        Err(errno::from_i32(e))
    }
}

/// Load siginfo register information from ptrace
///
/// Return the siginfo contents, or, a zero'd block if the signal cannot be fetched
pub fn ptrace_getsiginfo(task: &Task) -> Vec<u8> {
    trace!("ptrace_getsiginfo for tid: {}", task.tid);
    let siginfo_bytes: [u8; size_of::<libc::siginfo_t>()] =
        match ptrace::getsiginfo(Pid::from_raw(task.tid)) {
            Err(x) => {
                if x != nix::errno::Errno::EINVAL {
                    // group stop is normal, ignore it
                    eprintln!(
                        "failed to getsiginfo for tid {}, assuming 0s, : {}",
                        task.tid, x
                    );
                }
                [0; size_of::<libc::siginfo_t>()]
            }
            Ok(s) => {
                let mut sl = [0; size_of::<libc::siginfo_t>()];
                sl.copy_from_slice(siginfo_to_bytes(&s));
                sl
            }
        };

    siginfo_bytes.to_vec()
}

/// Load siginfo register information from ptrace
///
/// Returns the siginfo contents, or a 0'd result if the signal cannot be fetched
pub fn ptrace_getsiginfo_or_zeros(tid: Pid) -> elf_siginfo {
    trace!("ptrace_getsiginfo for tid: {}", tid);
    match ptrace::getsiginfo(tid) {
        Err(x) => {
            // group stop is normal, ignore it, but log everything else
            if x != nix::errno::Errno::EINVAL {
                warn!("failed to getsiginfo for tid {}, assuming 0s, : {}", tid, x);
            }
            elf_siginfo {
                si_signo: 0,
                si_code: 0,
                si_errno: 0,
            }
        }
        Ok(s) => elf_siginfo {
            si_signo: s.si_signo,
            si_code: s.si_code,
            si_errno: s.si_errno,
        },
    }
}

// Platform-specific code below here

#[cfg(not(target_arch = "x86_64"))]
pub fn ptrace_get_regset_size(task: &Task) -> Result<Option<usize>, Errno> {
    Ok(None)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn ptrace_get_regset(task: &Task) -> Result<Option<Vec<u8>>, Errno> {
    Ok(None)
}

#[cfg(target_arch = "x86_64")]
pub fn ptrace_get_regset_size(task: &Task) -> Result<Option<usize>, Errno> {
    trace!("ptrace_get_regset_size x86_64 for task: {}", task.tid);
    Ok(ptrace_get_regset(task)?.map(|r| r.len()))
}

/// Load x86_xstate register information from ptrace
#[cfg(target_arch = "x86_64")]
pub fn ptrace_get_regset(task: &Task) -> Result<Option<Vec<u8>>, Errno> {
    trace!("ptrace_get_regset x86_64 for task: {}", task.tid);
    let mut x86state: [u8; X86_XSTATE_MAX_SIZE as usize] = [0; X86_XSTATE_MAX_SIZE as usize];
    let mut iovec = libc::iovec {
        iov_base: x86state.as_mut_ptr() as *mut libc::c_void,
        iov_len: x86state.len(),
    };

    // out of sympathy for GETFPREGS (see ptrace_get_fpregset)
    let ptrace_res: c_long =
        unsafe { libc::ptrace(PTRACE_GETREGSET, task.tid, NT_X86_XSTATE, &mut iovec) };
    let e: i32 = errno();

    if ptrace_res != -1 {
        // TODO truncating results in a gdb warning since it truncates the state size and
        //      gdb wants a full sized note; not really sure what the right answer is
        //      here since we should probably follow ptrace, which means anything longer
        //      than iov_len is undefined data
        Ok(Some((x86state[..iovec.iov_len]).to_vec()))
    } else {
        Err(errno::from_i32(e))
    }
}
