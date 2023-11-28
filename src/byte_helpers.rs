// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Helpers to manipulate the ELF file structs and bytes.

use std::io;

use libc::siginfo_t;
use libelf_sys::*;

use crate::linux::{Prpsinfo, Prstatus};

/// Round up a value to 4's.
///
/// This allows for address alignment at 4-byte intervals for the ELF structures.
pub const fn align_4(addr: usize) -> usize {
    ((addr) + 3) & (!3)
}

/// Pad output contents to 4-bytes wide
pub fn pad_to_4(written: usize, output: &mut impl io::Write) -> Result<(), std::io::Error> {
    let to_write = align_4(written) - written;
    for _ in 0..to_write {
        output.write_all(&[0_u8])?;
    }

    Ok(())
}

/// Represent a Elf64_Ehdr as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn ehdr_to_bytes(ehdr: &Elf64_Ehdr) -> &[u8] {
    unsafe { any_as_u8_slice(ehdr) }
}

/// Represent a Elf64_Nhdr as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn nhdr_to_bytes(nhdr: &Elf64_Nhdr) -> &[u8] {
    unsafe { any_as_u8_slice(nhdr) }
}

/// Represent a Elf64_Phdr as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn phdr_to_bytes(phdr: &Elf64_Phdr) -> &[u8] {
    unsafe { any_as_u8_slice(phdr) }
}

/// Represent a prstatus as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn prstatus_to_bytes(prstatus: &Prstatus) -> &[u8] {
    unsafe { any_as_u8_slice(prstatus) }
}

/// Represent a prpsinfo as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn prpsinfo_to_bytes(prpsinfo: &Prpsinfo) -> &[u8] {
    unsafe { any_as_u8_slice(prpsinfo) }
}

/// Represent a siginfo_t as bytes for ELF file.
///
/// This is a view over the underlying struct.
pub fn siginfo_to_bytes(siginfo: &siginfo_t) -> &[u8] {
    unsafe { any_as_u8_slice(siginfo) }
}

/// Convert any struct value to the &[u8] read-only slice representation
/// of the value in raw memory.
///
/// This allows for a constructed value to be written out to disk precisely as
/// it appears in memory. Of course, the memory layout needs to be correct,
/// which is defined specifically for the relevant types in the
/// bindings.rs/wrappers.h configuration.
unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    // https://stackoverflow.com/a/42186553
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

#[cfg(test)]
mod tests {
    use std::io::Error;

    use crate::byte_helpers::align_4;

    use super::pad_to_4;

    #[test]
    fn test_align_4() {
        assert_eq!(0, align_4(0));
        assert_eq!(4, align_4(1));
        assert_eq!(4, align_4(2));
        assert_eq!(4, align_4(3));
        assert_eq!(4, align_4(4));
        assert_eq!(8, align_4(5));
        assert_eq!(8, align_4(6));
        assert_eq!(8, align_4(7));
        assert_eq!(8, align_4(8));
        assert_eq!(12, align_4(9));
    }

    #[test]
    fn test_pad_to_4() -> Result<(), Error> {
        let mut buffer = vec![0_u8];
        buffer.clear();

        pad_to_4(0, &mut buffer)?;
        assert_eq!(0, buffer.len());
        buffer.clear();

        pad_to_4(1, &mut buffer)?;
        assert_eq!(3, buffer.len());
        buffer.clear();

        pad_to_4(2, &mut buffer)?;
        assert_eq!(2, buffer.len());
        buffer.clear();

        pad_to_4(3, &mut buffer)?;
        assert_eq!(1, buffer.len());
        buffer.clear();

        pad_to_4(4, &mut buffer)?;
        assert_eq!(0, buffer.len());
        buffer.clear();

        pad_to_4(5, &mut buffer)?;
        assert_eq!(3, buffer.len());
        buffer.clear();

        pad_to_4(6, &mut buffer)?;
        assert_eq!(2, buffer.len());
        buffer.clear();

        pad_to_4(7, &mut buffer)?;
        assert_eq!(1, buffer.len());
        buffer.clear();

        pad_to_4(8, &mut buffer)?;
        assert_eq!(0, buffer.len());
        buffer.clear();

        pad_to_4(9, &mut buffer)?;
        assert_eq!(3, buffer.len());
        buffer.clear();

        pad_to_4(10, &mut buffer)?;
        assert_eq!(2, buffer.len());
        buffer.clear();

        pad_to_4(11, &mut buffer)?;
        assert_eq!(1, buffer.len());
        buffer.clear();

        pad_to_4(12, &mut buffer)?;
        assert_eq!(0, buffer.len());
        buffer.clear();

        Ok(())
    }
}