// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Read process memory directly from a target process with process_vm_readv.
//!
//! To save some IO, we also use the pagemap entry flags in /proc/../pagemap
//! to get an understanding of which pages are present in memory. This will
//! likely cause problems if something swapped out, but avoids us paging in
//! the file contents.
//!
//! More info on the pagemap here:
//!   http://fivelinesofcode.blogspot.com/2014/03/how-to-translate-virtual-to-physical.html

use crate::sysconf;
use fallible_streaming_iterator::FallibleStreamingIterator;
use nix::sys::uio::process_vm_readv;
use nix::sys::uio::RemoteIoVec;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use thiserror::Error;

// the [vsyscall] region of memory is well-known, but also triggers
// a false error if we try to read it; simplest is to bypass the region
// altogether
const ADDR_VSYSCALL: usize = 0xffffffffff600000;

// max buffer size for process_vm_readv processing
const MAX_BUFFER_SIZE: usize = 256 * 1024;

// size in bytes of a single pagemap entry
const PAGEMAP_ENTRY_SIZE: usize = 8;
// bit from the entry which indicates whether the page is present
const PAGEMAP_PRESENT_BIT: u64 = 63;

static EMPTY_PAGE: Lazy<Vec<u8>> = Lazy::new(|| vec![0; sysconf::sc_page_size()]);

#[derive(Error, Debug)]
pub enum ProcessMemoryError {
    #[error("error performing IO on pagemap")]
    PagemapIo(#[from] io::Error),

    #[error("did not read correct length, wanted {wanted:?}, got {got:?}")]
    ReadLength { wanted: usize, got: usize },

    #[error("error calling process_vm_readv")]
    ProcessVmReadv(#[from] nix::errno::Errno),
}

/// A pagemap entry represents a single page of memory from the
/// /proc/pid/pagemap file
pub struct PagemapEntry {
    entry_val: u64,
}

impl PagemapEntry {
    /// Is the page present/readable?
    pub fn is_readable(&self) -> bool {
        (self.entry_val >> PAGEMAP_PRESENT_BIT & 1) == 1
    }
}

impl From<[u8; 8]> for PagemapEntry {
    /// Realize a pagemap read from the pagemap file
    fn from(bytes: [u8; 8]) -> Self {
        PagemapEntry {
            // TODO is this native order, or specific endian?
            entry_val: u64::from_le_bytes(bytes),
        }
    }
}

/// Represents an opened process ready for reading.
pub struct ProcessMemory {
    pid: libc::pid_t,
    pagemap_file: BufReader<File>,
}

/// A StreamingIterator that allows reading from another process' memory space.
///
/// The iterator makes attempts to be efficient with buffering to minimise
/// excessive calls to the linux process_vm_readv syscall.
pub struct ProcessMemoryStreamingIterator {
    pid: nix::unistd::Pid,
    pagemap_entries: Vec<PagemapEntry>,
    next_page_number: usize,
    offset: usize,
    buffer: Vec<u8>,
    done: bool,

    // Zero marking is supported to avoid spending time copying around 0s
    // in the event we will be writting a zero page
    zero_page: bool,
}

impl ProcessMemoryStreamingIterator {
    /// Create a new streaming iterator over the memory region, starting at offset
    /// and running for pagemap_entries.len() pages long.
    pub fn new(pid: libc::pid_t, offset: usize, pagemap_entries: Vec<PagemapEntry>) -> Self {
        ProcessMemoryStreamingIterator {
            pid: Pid::from_raw(pid),
            pagemap_entries,
            next_page_number: 0,
            offset,
            buffer: vec![0; MAX_BUFFER_SIZE],
            done: false,
            zero_page: true,
        }
    }

    /// Mark next read as clear (zero) page
    fn mark_zero(&mut self) {
        self.zero_page = true;
    }

    // Mark next read as normal / dirty page
    fn mark_not_zero(&mut self) {
        self.zero_page = false;
    }
}

impl FallibleStreamingIterator for ProcessMemoryStreamingIterator {
    type Item = Vec<u8>;
    type Error = ProcessMemoryError;

    /// Advance the iterator
    fn advance(&mut self) -> Result<(), Self::Error> {
        // iterator is done
        if self.done || self.next_page_number >= self.pagemap_entries.len() {
            self.done = true;
            return Ok(());
        }

        // if page is not present/readable, we will send an empty page
        if !self
            .pagemap_entries
            .get(self.next_page_number)
            .unwrap()
            .is_readable()
        {
            self.mark_zero();
            self.next_page_number += 1;
            return Ok(());
        }

        // happy path: page is resident in memory and can be copied like normal

        // batch as many readable pages as we can together in a row
        // .. up to the buffer size
        let count_pages = self.pagemap_entries[self.next_page_number..]
            .iter()
            .take_while(|x| x.is_readable())
            .take(MAX_BUFFER_SIZE / sysconf::sc_page_size())
            .count();

        // set up the iovec memory and pointers for vm_readv
        self.buffer.resize(count_pages * sysconf::sc_page_size(), 0);
        self.mark_not_zero();
        let remote = RemoteIoVec {
            base: self.offset + (self.next_page_number * sysconf::sc_page_size()),
            len: count_pages * sysconf::sc_page_size(),
        };
        let local = io::IoSliceMut::new(&mut self.buffer);

        // do process_vm_readv syscall
        let actually_read = process_vm_readv(self.pid, &mut [local], &[remote])?;

        // check the results
        if actually_read != (count_pages * sysconf::sc_page_size()) {
            return Err(ProcessMemoryError::ReadLength {
                wanted: (count_pages * sysconf::sc_page_size()),
                got: actually_read,
            });
        }

        self.next_page_number += count_pages;
        Ok(())
    }

    /// Get a reference to the next buffer available to be processed
    fn get(&self) -> Option<&Self::Item> {
        if self.done {
            None
        } else if self.zero_page {
            Some(&EMPTY_PAGE)
        } else {
            Some(&self.buffer)
        }
    }
}

/// Provide access to a target process' memory space
impl ProcessMemory {
    /// Create a new ProcessMemory object wrapping the pid
    pub fn new(pid: libc::pid_t) -> Result<Self, ProcessMemoryError> {
        let pagemap_file = fs::File::open(format!("/proc/{pid}/pagemap"))?;

        Ok(ProcessMemory {
            pid,
            pagemap_file: BufReader::new(pagemap_file),
        })
    }

    /// Read pagemap information for the target process
    pub fn read_pagemap_range(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<Vec<PagemapEntry>, ProcessMemoryError> {
        let page_size = sysconf::sc_page_size();

        let count_pages: usize = length / page_size;
        let pagemap_offset = offset / (page_size / PAGEMAP_ENTRY_SIZE);

        self.pagemap_file
            .seek(io::SeekFrom::Start(pagemap_offset as u64))?;

        let mut pagemaps: Vec<PagemapEntry> = Vec::new();

        // read exactly 8 bytes at a time
        let mut bytes = [0; 8];
        for _ in 0..count_pages {
            self.pagemap_file.read_exact(&mut bytes)?;
            pagemaps.push(PagemapEntry::from(bytes));
        }

        Ok(pagemaps)
    }

    /// Read memory from the target process
    pub fn read_memory(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<ProcessMemoryStreamingIterator, ProcessMemoryError> {
        let entries: Vec<PagemapEntry> = if offset == ADDR_VSYSCALL {
            Vec::new()
        } else {
            self.read_pagemap_range(offset, length)?
        };

        Ok(ProcessMemoryStreamingIterator::new(
            self.pid, offset, entries,
        ))
    }
}
