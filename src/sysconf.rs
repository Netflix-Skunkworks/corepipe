// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
use log::trace;
use nix::unistd::{sysconf, SysconfVar};
use once_cell::sync::OnceCell;
use thiserror::Error;

static SC_CLK_TCK: OnceCell<u64> = OnceCell::new();
static SC_PAGE_SIZE: OnceCell<usize> = OnceCell::new();

#[derive(Error, Debug)]
pub enum SysconfError {
    #[error("already initialized")]
    AlreadyInitialized,

    #[error("unable to load clk_tck sysconf")]
    ClockTickError,

    #[error("clk_tck sysconf has no value")]
    ClockTickMissing,

    #[error("unable to load page_size sysconf")]
    PageSizeError,

    #[error("page_size sysconf has no value")]
    PageSizeMissing,
}

/// Trigger initialize of system-wide sysconf values
///
/// Do this early to ensure that we don't have any surprises later.
pub fn load_sysconfs() -> Result<(), SysconfError> {
    let clk_tck: u64 = match sysconf(SysconfVar::CLK_TCK) {
        Ok(Some(v)) => v as u64,
        Ok(None) => return Err(SysconfError::ClockTickMissing),
        Err(_) => return Err(SysconfError::ClockTickError),
    };
    trace!("load_sysconfs(): CLK_TCK = {}", clk_tck);

    let page_size: usize = match sysconf(SysconfVar::PAGE_SIZE) {
        Ok(Some(v)) => v as usize,
        Ok(None) => return Err(SysconfError::PageSizeMissing),
        Err(_) => return Err(SysconfError::PageSizeError),
    };
    trace!("load_sysconfs(): PAGE_SIZE = {}", page_size);

    if SC_CLK_TCK.set(clk_tck).is_err() {
        return Err(SysconfError::AlreadyInitialized);
    }

    if SC_PAGE_SIZE.set(page_size).is_err() {
        return Err(SysconfError::AlreadyInitialized);
    }

    Ok(())
}

pub fn sc_clk_tck() -> u64 {
    *SC_CLK_TCK.get().unwrap()
}
pub fn sc_page_size() -> usize {
    *SC_PAGE_SIZE.get().unwrap()
}
