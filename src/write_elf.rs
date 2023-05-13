// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Support for writing ELF files to an output.

use std::cmp;
use std::collections::HashMap;
use std::io::{self, BufWriter, Write};
use std::mem::size_of;

use crate::bindings::{fpregs, prpsinfo, prstatus};
use crate::byte_helpers::*;
use crate::process_memory::ProcessMemory;
use crate::smaps::SmapRange;
use fallible_streaming_iterator::FallibleStreamingIterator;
use libelf_sys::*;
use log::{debug, info, trace, warn};

// Special ELF-file text values
const NOTE_NAME_CORE: &[u8; 8] = b"CORE\0\0\0\0";
const NOTE_NAME_LINUX: &[u8; 8] = b"LINUX\0\0\0";

#[cfg(target_arch = "x86_64")]
const ELF_MACHINE_ID: Elf64_Half = EM_X86_64 as Elf64_Half;
#[cfg(target_arch = "x86_64")]
const ELF_MACHINE_REGISTER_NOTE_TYPE: Elf64_Word = NT_X86_XSTATE;

/// Determine the size for a note name;
///
/// Whilst the note name field is 8 bytes long, the size is also
/// emitted and needs to include the optional null terminator
const fn note_name_size(name: &[u8; 8]) -> u32 {
    // this is done painfully since it is a const function

    // clunky to allow for null terminator
    let mut idx = 0;
    let mut count_non_zero = 0;
    while idx < name.len() {
        if name[idx] != 0 {
            count_non_zero += 1;
        }
        idx += 1;
    }

    // allow for the null terminator
    count_non_zero + 1
}

/// Confirm whether an SmapRange memory range should be dumped.
///
/// Conditions are:
/// - range must be dumpable (VmFlags: dd don't dump) cannot be set
/// - has to have useful / dirty information contents (ie: not a regular file)
/// - or, is a regular file that has been deleted, or a file without an inode
/// - cannot be a vdso / vsyscall region
fn should_dump_range(range: &SmapRange) -> bool {
    // mapping has to be dumpable
    if range.flag_dd {
        return false;
    }

    // pages with information
    if range.anonymous > 0 || range.private_dirty > 0 || range.shared_dirty > 0 {
        return true;
    }

    // always dump vdso and vsyscall, or, ..
    // if not mapped to a file, or filename is deleted
    match range.pathname.as_deref() {
        Some("[vdso]") => return true,
        Some("[vsyscall]") => return true,
        Some(x) if x.is_empty() => return true,
        Some(x) if x.contains("(deleted)") => return true,
        None => return true,
        _ => {}
    };

    // not mapped to a file
    if range.inode == 0 {
        return true;
    }

    // everything else left behind
    false
}

/// Write an ELF Ehdr
pub fn write_elf_header(
    smaps: &[SmapRange],
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    let num_load_sections = smaps.iter().filter(|r| should_dump_range(r)).count() as u16;
    let ident: [u8; 16] = [
        ELFMAG0 as u8,
        ELFMAG1,
        ELFMAG2,
        ELFMAG3,
        ELFCLASS64 as u8,
        ELFDATA2LSB as u8,
        EV_CURRENT as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let ehdr: Elf64_Ehdr = Elf64_Ehdr {
        e_ident: ident,
        e_type: ET_CORE as Elf64_Half,
        e_machine: ELF_MACHINE_ID,
        e_version: EV_CURRENT,
        e_entry: 0,
        e_phoff: size_of::<Elf64_Ehdr>() as Elf64_Off, /* start immediately after Ehdr */
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: size_of::<Elf64_Ehdr>() as Elf64_Half,
        e_phentsize: size_of::<Elf64_Phdr>() as Elf64_Half,
        e_phnum: num_load_sections + 1, /* add a note section */
        e_shentsize: 0,                 /* no section mappings, not required */
        e_shnum: 0,
        e_shstrndx: 0,
    };

    output.write_all(ehdr_to_bytes(&ehdr))?;

    Ok(())
}

/// Write a simple structured ELF note, including header, contents, and padding.
fn write_simple_note(
    note_name: &[u8; 8],
    note_type: u32,
    note_description: &[u8],
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    output.write_all(nhdr_to_bytes(&Elf64_Nhdr {
        n_namesz: note_name_size(note_name),
        n_descsz: note_description.len() as Elf64_Word,
        n_type: note_type,
    }))?;
    output.write_all(note_name)?;
    output.write_all(note_description)?;
    pad_to_4(note_description.len(), output)?;

    Ok(())
}

/// Write a NT_PRSTATUS note
pub fn write_note_prstatus(
    prs: prstatus,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    write_simple_note(NOTE_NAME_CORE, NT_PRSTATUS, prstatus_to_bytes(&prs), output)
}

/// Write a NT_FPREGSET note
pub fn write_note_fpregset(
    fpregs: Vec<u8>,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    write_simple_note(NOTE_NAME_CORE, NT_FPREGSET, &fpregs, output)
}

/// Write a general register note
pub fn write_note_regset(
    registers: Vec<u8>,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    write_simple_note(
        NOTE_NAME_LINUX,
        ELF_MACHINE_REGISTER_NOTE_TYPE,
        &registers,
        output,
    )
}

/// Write a NT_SIGINFO note
pub fn write_note_siginfo(
    siginfo: Vec<u8>,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    write_simple_note(NOTE_NAME_CORE, NT_SIGINFO, &siginfo, output)
}

/// Write note NT_AUXV
pub fn write_note_auxv(
    auxv_table: HashMap<u64, u64>,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    let mut description = vec![0_u8; 0];
    for (key, val) in auxv_table.iter() {
        description.extend(u64::to_ne_bytes(*key));
        description.extend(u64::to_ne_bytes(*val));
    }

    write_simple_note(NOTE_NAME_CORE, NT_AUXV, &description, output)
}

/// Write note NT_PRPSINFO
pub fn write_note_prpsinfo(
    procfs_info: prpsinfo,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    write_simple_note(
        NOTE_NAME_CORE,
        NT_PRPSINFO,
        prpsinfo_to_bytes(&procfs_info),
        output,
    )
}

/// Write note NT_FILE for memory mapped files
pub fn write_note_mapped_files(
    smaps: &[SmapRange],
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    //
    // https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c#L1593-L1603
    // Format of NT_FILE note:
    //
    // long count     -- how many files are mapped
    // long page_size -- units for file_ofs
    // array of [COUNT] elements of
    //   long start
    //   long end
    //   long file_ofs
    // followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
    //
    let description_length = calc_note_mapped_files_descr_length(smaps);
    let nhdr = Elf64_Nhdr {
        n_namesz: 5,
        n_descsz: description_length as Elf64_Word,
        n_type: NT_FILE,
    };

    let mapping_count: u64 = smaps.iter().filter(|r| should_make_nt_file(r)).count() as u64;
    let page_size: u64 = 1;

    output.write_all(nhdr_to_bytes(&nhdr))?;
    output.write_all(NOTE_NAME_CORE)?;
    output.write_all(&mapping_count.to_ne_bytes())?;
    output.write_all(&page_size.to_ne_bytes())?;

    for range in smaps.iter().filter(|r| should_make_nt_file(r)) {
        output.write_all(&range.address_start.to_ne_bytes())?;
        output.write_all(&range.address_end.to_ne_bytes())?;
        output.write_all(&range.offset.to_ne_bytes())?;
    }

    for range in smaps.iter().filter(|r| should_make_nt_file(r)) {
        let to_write: &[u8] = match range.pathname.as_deref() {
            Some(s) => s.as_bytes(),
            None => &[],
        };

        output.write_all(to_write)?;
        output.write_all(&[0])?;
    }

    pad_to_4(description_length, output)?;

    Ok(())
}

/// Write an ELF program header to cover a given Range
///
/// It is assumed that the contents in the program header will be written to corefile later
fn create_program_header_load_section(range: &SmapRange) -> Elf64_Phdr {
    let mut flags = 0;
    flags |= range.is_r as u32 * PF_R;
    flags |= range.is_w as u32 * PF_W;
    flags |= range.is_x as u32 * PF_X;

    let filesz = if range.is_prot_none() {
        0
    } else {
        range.address_end - range.address_start
    } as u64;
    let memsz = (range.address_end - range.address_start) as u64;

    Elf64_Phdr {
        p_type: PT_LOAD,
        // set offset to 0 but we will do an offset fixup later
        // in write_program_header
        p_offset: 0,
        p_vaddr: range.address_start as Elf64_Addr,
        p_paddr: 0x0,
        p_filesz: filesz,
        p_memsz: memsz,
        p_flags: flags,
        p_align: 0x1,
        // file contents
    }
}

/// Write all ELF program headers in a block
pub fn write_program_header(
    smaps: &[SmapRange],
    auxv_table: &HashMap<u64, u64>,
    num_tasks: usize,
    register_size: Option<usize>,
    output: &mut impl io::Write,
) -> Result<(), std::io::Error> {
    let mut phdrs = Vec::new();

    // each program header refers to the offset and size of the previous;
    // it's a little easier to construct them all at the same time ..
    phdrs.push(create_program_header_note_section(
        smaps,
        auxv_table,
        num_tasks,
        register_size,
    ));
    for range in smaps.iter().filter(|r| should_dump_range(r)) {
        phdrs.push(create_program_header_load_section(range));
    }

    // .. and then fix up the offsets afterwards
    for idx in 1..phdrs.len() {
        phdrs[idx].p_offset = phdrs[idx - 1].p_offset + phdrs[idx - 1].p_filesz;
    }

    for phdr in phdrs {
        output.write_all(phdr_to_bytes(&phdr))?;
    }

    Ok(())
}

/// Write an ELF program header to cover the notes sections
pub fn create_program_header_note_section(
    smaps: &[SmapRange],
    auxv_table: &HashMap<u64, u64>,
    num_tasks: usize,
    register_size: Option<usize>,
) -> Elf64_Phdr {
    const NAMESZ: usize = 8;
    const SIZEOF_NHDR: usize = size_of::<Elf64_Nhdr>();
    const SIZEOF_EHDR: usize = size_of::<Elf64_Ehdr>();
    const SIZEOF_PHDR: usize = size_of::<Elf64_Phdr>();

    let num_load_sections = smaps.iter().filter(|r| should_dump_range(r)).count() as u64;
    let note_mapped_files_descr_length = calc_note_mapped_files_descr_length(smaps);

    // the size of a note is:
    // - a note header
    //   the note header includes the lengths but not the values of the name & data
    // - room for the name (NAMESZ - is 8 bytes), either CORE or LINUX
    // - the data (description), which varies by note type

    // notes section will contain:
    // one:
    // - NT_PRPSINFO
    // then, for each thread:
    // - NT_PRSTATUS
    // - NT_FPREGSET
    // - NT_X86_XSTATE (or similar)
    // - NT_SIGINFO
    // followed by one each of:
    // - NT_AUXV
    // - NT_FILE

    let mut notesize = 0;

    // NT_PRPSINFO
    notesize += SIZEOF_NHDR + NAMESZ + align_4(size_of::<prpsinfo>());
    // NT_PRSTATUS
    notesize += num_tasks * (SIZEOF_NHDR + NAMESZ + align_4(size_of::<prstatus>()));
    // NT_FPREGSET
    notesize += num_tasks * (SIZEOF_NHDR + NAMESZ + align_4(size_of::<fpregs>()));
    // NT_X86_XSTATE / general registers
    if let Some(size) = register_size {
        notesize += num_tasks * (SIZEOF_NHDR + NAMESZ + align_4(size));
    }
    // NT_SIGINFO
    notesize += num_tasks * (SIZEOF_NHDR + NAMESZ + align_4(size_of::<libc::siginfo_t>()));
    // NT_AUXV
    notesize += SIZEOF_NHDR + NAMESZ + align_4(auxv_table.len() * size_of::<Elf64_auxv_t>());
    // NT_FILE
    notesize += SIZEOF_NHDR + NAMESZ + align_4(note_mapped_files_descr_length);

    let offset = SIZEOF_EHDR + SIZEOF_PHDR * (1 + num_load_sections as usize);

    Elf64_Phdr {
        p_type: PT_NOTE,
        // first section will start after all headers
        p_offset: offset as Elf64_Off,
        // no address mapping, this is a notes area
        p_vaddr: 0x0,
        p_paddr: 0x0,
        p_memsz: 0x0,
        // read only, 1-byte aligned (ie: not aligned)
        p_flags: PF_R,
        p_align: 0x1,
        // file contents
        p_filesz: notesize as Elf64_Xword,
    }
}

/// Calculate the length of the NT_FILE description entry
fn calc_note_mapped_files_descr_length(smaps: &[SmapRange]) -> usize {
    const LENGTH_MAPPINGS: usize = 8;
    const PAGE_SIZE: usize = 8;
    let notes_region_size = smaps
        .iter()
        .filter(|r| should_make_nt_file(r))
        // addr_start, addr_end, offset, pathname, null terminator
        .map(|r| 8 + 8 + 8 + r.pathname_len() + 1)
        .sum::<usize>();

    LENGTH_MAPPINGS + PAGE_SIZE + notes_region_size
}

/// Confirm if we should write a NT_FILE record for a memory mapped file
///
/// A file will be written if it is both marked dumpable in memory, and
/// either marked in memory as modified, or deleted from the underlying
/// file-system.
fn should_make_nt_file(range: &SmapRange) -> bool {
    // mapping has to be dumpable
    if range.flag_dd {
        return false;
    }

    // genuine files, either deleted (so, not available), or modified in memory
    if range.inode != 0 {
        if range.private_dirty > 0 || range.shared_dirty > 0 {
            return true;
        }
        match range.pathname.as_deref() {
            Some(x) if x.contains("(deleted)") => return true,
            _ => {}
        }
    }

    false
}

/// Write the ELF load section contents out to the file
///
/// They will be emitted in the same order as the SmapRange specifies.
///
/// Only ranges that are (a) should_dump_range(), and (b) are not fully protected pages,
/// will be emitted.
pub fn write_load_sections(
    smaps: &[SmapRange],
    mem: &mut ProcessMemory,
    output: &mut impl io::Write,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "writing load sections: total={}, eligible={}, approx load section bytes={}",
        smaps.len(),
        smaps
            .iter()
            .filter(|r| should_dump_range(r))
            .filter(|r| !r.is_prot_none())
            .count(),
        smaps
            .iter()
            .filter(|r| should_dump_range(r))
            .filter(|r| !r.is_prot_none())
            .map(|r| r.length)
            .sum::<usize>()
    );

    // pre-flush
    output.flush()?;

    // TODO ideally we could switch to a raw stdout
    // https://github.com/rust-lang/libs-team/issues/148

    let mut buff_out = BufWriter::with_capacity(64 * 1024, output);

    const READ_LENGTH: usize = 8 * 1024 * 1024;

    for range in smaps
        .iter()
        .filter(|r| should_dump_range(r))
        .filter(|r| !r.is_prot_none())
    {
        trace!(".. writing load section: {}", range);

        let mut start = range.address_start;

        // ordinarily we should be able to push this out to infinity, however
        // if the region is huge, the pagemap read might also be "big";
        // we can mitigate this by reading the page by some smaller distance

        while start < range.address_end {
            let length = cmp::min(READ_LENGTH, range.address_end - start);

            let mut buffers = mem.read_memory(range.address_start, length)?;
            while let Some(buff) = buffers.next()? {
                buff_out.write_all(buff)?;
            }

            start += length;
        }

        if start != range.address_end {
            warn!(
                "did not finish at the end?, start: {}, end: {}",
                start, range.address_end
            );
        }
    }

    trace!("flushing load section");
    buff_out.flush()?;

    debug!("load sections complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::write_elf::{note_name_size, NOTE_NAME_CORE};

    #[test]
    fn test_note_size_calculator() {
        assert_eq!(5, note_name_size(NOTE_NAME_CORE));
    }
}
