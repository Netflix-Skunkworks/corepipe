// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Parsing for /proc/$pid/smaps contents.
//!
//! Structure is in `man 5 proc` - including all of the special values that can be found in the field.
//!
//! 7fff757e6000-7fff757e9000 r--p 00000000 00:00 0                          [vvar]
//! Size:                 12 kB
//! KernelPageSize:        4 kB
//! ...                  ......
//! VmFlags: rd mr pf io de dd

use log::{debug, trace};
use nix::unistd::Pid;
use std::fmt::Display;
use std::fs;
use std::io;
use std::io::BufRead;
use thiserror::Error;

//
// Below SmapRange struct shape ONLY is from pmparser.h
//
// Added a set of extra fields to capture all needed /smap information
// Changed void* to char* for the addresses, since the addresses represent
//   addressable bytes
//
// https://github.com/ouadev/proc_maps_parser/blob/master/pmparser.h
//

/*
 @Author    : ouadimjamal@gmail.com
 @date      : December 2015

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.
*/

/// Represents a memory range entry as output in /proc/../smaps.
#[derive(Default)]
pub struct SmapRange {
    // start address of area
    pub address_start: usize,
    // end address
    pub address_end: usize,
    // size of the range
    pub length: usize,

    // rewrite of perm with small flags
    pub is_r: bool,
    pub is_w: bool,
    pub is_x: bool,
    pub is_p: bool,

    // offset
    pub offset: usize,

    // dev major:minor
    pub dev: String,

    // inode of the file that backs the area
    pub inode: u64,

    pub pathname: Option<String>,

    // extra data in /proc/pid/smaps
    pub size: u64,
    pub kernel_page_size: u64,
    pub mmu_page_size: u64,
    pub rss: u64,
    pub pss: u64,
    pub shared_clean: u64,
    pub shared_dirty: u64,
    pub private_clean: u64,
    pub private_dirty: u64,
    pub referenced: u64,
    pub anonymous: u64,
    pub lazy_free: u64,
    pub anon_huge_pages: u64,
    pub shmem_pmd_mapped: u64,
    pub shared_hugetlb: u64,
    pub private_hugetlb: u64,
    pub swap: u64,
    pub swap_pss: u64,
    pub locked: u64,

    pub thp_eligible: bool,

    // vmflags:
    // linux/fs/proc/task_mmu.c:show_smap_vma_flags
    pub flag_rd: bool,
    pub flag_wr: bool,
    pub flag_ex: bool,
    pub flag_sh: bool,
    pub flag_mr: bool,
    pub flag_mw: bool,
    pub flag_me: bool,
    pub flag_ms: bool,
    pub flag_gd: bool,
    pub flag_pf: bool,
    pub flag_dw: bool,
    pub flag_lo: bool,
    pub flag_io: bool,
    pub flag_sr: bool,
    pub flag_rr: bool,
    pub flag_dc: bool,
    pub flag_de: bool,
    pub flag_ac: bool,
    pub flag_nr: bool,
    pub flag_ht: bool,
    pub flag_ar: bool,
    pub flag_dd: bool,
    pub flag_sd: bool,
    pub flag_mm: bool,
    pub flag_hg: bool,
    pub flag_nh: bool,
    pub flag_mg: bool,
    pub flag_wf: bool,
}

impl SmapRange {
    /// Is the range not protected (prot_none), ie: cannot read or write or execute;
    /// usually reserved for secret contents or things that should otherwise not
    /// be exported.
    pub fn is_prot_none(&self) -> bool {
        let is_rwx = self.is_r || self.is_w || self.is_x;
        !is_rwx
    }

    /// Length of pathname, or 0 if no pathname is present.
    pub fn pathname_len(&self) -> usize {
        match &self.pathname {
            Some(x) => x.len(),
            None => 0,
        }
    }
}

impl Display for SmapRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SmapRange({:#018x}-{:#018x}, length={})",
            self.address_start, self.address_end, self.length
        )
    }
}

#[derive(Error, Debug)]
pub enum SmapError {
    #[error("unable performing IO on smaps file")]
    Io(#[from] io::Error),

    #[error("unable to parse mapping line: {reason:?}")]
    MappingLine { reason: String },

    #[error("unable to parse detail line: {reason:?}")]
    DetailLine { reason: String },

    #[error("found detail line when no mappings have been set up yet")]
    DetailLineEarly,

    #[error("unable to parse field in detail line")]
    DetailLineValue(#[from] std::num::ParseIntError),

    #[error("found vmflags line when no mappings have been set up yet")]
    VmFlagsLineEarly,
}

/// Read /proc/pid/smaps contents for a given PID
pub fn read_smaps(pid: Pid) -> Result<Vec<SmapRange>, SmapError> {
    let smaps_name = format!("/proc/{pid}/smaps");
    read_smaps_file(smaps_name)
}

/// Reads smaps from a given file
fn read_smaps_file(filename: String) -> Result<Vec<SmapRange>, SmapError> {
    debug!("read_smaps_file {}", filename);
    let file = fs::File::open(filename)?;
    let reader = io::BufReader::new(file);
    let file_lines = reader.lines();

    parse_smaps(file_lines)
}

/// Parse smaps file contents, returning a Vec<SmapRange>
fn parse_smaps(
    smaps_lines: impl Iterator<Item = Result<String, io::Error>>,
) -> Result<Vec<SmapRange>, SmapError> {
    trace!("parsing smaps");
    let mut result = Vec::new();

    for line_wrapped in smaps_lines {
        let line = line_wrapped?;

        match detect_line_type(&line) {
            LineType::Mapping => {
                let mut next = SmapRange::default();
                parse_smaps_mapping_line_into(&line, &mut next)?;
                result.push(next);
            }
            LineType::Detail => {
                let next = result.last_mut().ok_or(SmapError::DetailLineEarly)?;
                parse_smaps_detail_line_into(&line, next)?;
            }
            LineType::VmFlags => {
                let next = result.last_mut().ok_or(SmapError::VmFlagsLineEarly)?;
                parse_smaps_vmflags_line_into(&line, next);
            }
        }
    }

    trace!("parse_smaps, found {} entries", result.len());
    Ok(result)
}

/// There are three types of lines in a smaps file.
enum LineType {
    Mapping,
    Detail,
    VmFlags,
}

/// Detect the LineType for a given line in the smaps file.
fn detect_line_type(str: &str) -> LineType {
    let is_alpha: bool = str.starts_with(|c: char| c.is_ascii_uppercase());
    let is_vmflags: bool = str.starts_with("VmFlags:");
    let is_mapping_line: bool = !is_vmflags && !is_alpha;

    if is_mapping_line {
        LineType::Mapping
    } else if is_vmflags {
        LineType::VmFlags
    } else {
        LineType::Detail
    }
}

/// Parse a single smaps `Mapping` line, filling out an SmapRange
fn parse_smaps_mapping_line_into(line: &str, range: &mut SmapRange) -> Result<(), SmapError> {
    let (addr_start, addr_end, perm, offset, dev, inode, pathname) = scan_fmt_some!(line, "{[0-9a-f]}-{[0-9a-f]} {} {x} {} {} {/.*/}",
        [hex usize], [hex usize], String, [hex usize], String, u64, String);

    range.address_start = addr_start.ok_or(SmapError::MappingLine {
        reason: "addr_start not parsed".to_string(),
    })?;
    range.address_end = addr_end.ok_or(SmapError::MappingLine {
        reason: "addr_end not parsed".to_string(),
    })?;
    range.offset = offset.ok_or(SmapError::MappingLine {
        reason: "offset not parsed".to_string(),
    })?;
    range.dev = dev.ok_or(SmapError::MappingLine {
        reason: "dev not parsed".to_string(),
    })?;
    range.inode = inode.ok_or(SmapError::MappingLine {
        reason: "inode not parsed".to_string(),
    })?;
    range.pathname = pathname;

    // calculated
    range.length = range.address_end - range.address_start;

    let perms = perm
        .as_ref()
        .ok_or(SmapError::MappingLine {
            reason: "perms not parsed".to_string(),
        })?
        .as_bytes();
    range.is_r = perms[0] == b'r';
    range.is_w = perms[1] == b'w';
    range.is_x = perms[2] == b'x';
    range.is_p = perms[3] == b'p';

    Ok(())
}

/// Parse a smaps `Detail` line, updating the SmapRange with the new detail
fn parse_smaps_detail_line_into(line: &str, range: &mut SmapRange) -> Result<(), SmapError> {
    let mut field_iter = line.split_whitespace();
    let field = field_iter.next().ok_or(SmapError::DetailLine {
        reason: "empty line".to_string(),
    })?;
    let value = field_iter
        .next()
        .ok_or(SmapError::DetailLine {
            reason: "value field missing".to_string(),
        })?
        .parse::<u64>()?;

    // most values are printed in the file as nnnn kB, decode appropriately to
    // bytes by multiplying
    let multiplication = match field_iter.next() {
        Some("kB") => Ok(4096),
        None => Ok(1),
        Some(x) => Err(SmapError::DetailLine {
            reason: format!("unknown detail line scale: {}", x),
        }),
    }?;

    match field {
        "Size:" => range.size = value * multiplication,
        "KernelPageSize:" => range.kernel_page_size = value * multiplication,
        "MMUPageSize:" => range.mmu_page_size = value * multiplication,
        "Rss:" => range.rss = value * multiplication,
        "Pss:" => range.pss = value * multiplication,
        "Shared_Clean:" => range.shared_clean = value * multiplication,
        "Shared_Dirty:" => range.shared_dirty = value * multiplication,
        "Private_Clean:" => range.private_clean = value * multiplication,
        "Private_Dirty:" => range.private_dirty = value * multiplication,
        "Referenced:" => range.referenced = value * multiplication,
        "Anonymous:" => range.anonymous = value * multiplication,
        "LazyFree:" => range.lazy_free = value * multiplication,
        "AnonHugePages:" => range.anon_huge_pages = value * multiplication,
        "ShmemPmdMapped:" => range.shmem_pmd_mapped = value * multiplication,
        "Shared_Hugetlb:" => range.shared_hugetlb = value * multiplication,
        "Private_Hugetlb:" => range.private_hugetlb = value * multiplication,
        "Swap:" => range.swap = value * multiplication,
        "SwapPss:" => range.swap_pss = value * multiplication,
        "Locked:" => range.locked = value * multiplication,
        _ => { /* ignored */ }
    }

    Ok(())
}

/// Parse a smaps `VmFlags` line, updating the SmapRange with the values
fn parse_smaps_vmflags_line_into(line: &str, range: &mut SmapRange) {
    let split = line.split_whitespace();
    for s in split {
        match s {
            "VmFlags:" => {}
            "rd" => range.flag_rd = true,
            "wr" => range.flag_wr = true,
            "ex" => range.flag_ex = true,
            "sh" => range.flag_sh = true,
            "mr" => range.flag_mr = true,
            "mw" => range.flag_mw = true,
            "me" => range.flag_me = true,
            "ms" => range.flag_ms = true,
            "gd" => range.flag_gd = true,
            "pf" => range.flag_pf = true,
            "dw" => range.flag_dw = true,
            "lo" => range.flag_lo = true,
            "io" => range.flag_io = true,
            "sr" => range.flag_sr = true,
            "rr" => range.flag_rr = true,
            "dc" => range.flag_dc = true,
            "de" => range.flag_de = true,
            "ac" => range.flag_ac = true,
            "nr" => range.flag_nr = true,
            "ht" => range.flag_ht = true,
            "ar" => range.flag_ar = true,
            "dd" => range.flag_dd = true,
            "sd" => range.flag_sd = true,
            "mm" => range.flag_mm = true,
            "hg" => range.flag_hg = true,
            "nh" => range.flag_nh = true,
            "mg" => range.flag_mg = true,
            "wf" => range.flag_wf = true,
            "" => {}
            flag => eprintln!("skipping vmflag: {}", flag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn parses_mapping_line_no_file() -> Result<(), SmapError> {
        let input = "7fa450000000-7fa450021000 rw-p 00000000 00:00 0";
        let mut result = SmapRange::default();
        parse_smaps_mapping_line_into(&input, &mut result)?;
        assert_eq!(0x7fa450000000, result.address_start);
        assert_eq!(0x7fa450021000, result.address_end);
        assert_eq!(0x0, result.offset);
        assert_eq!("00:00", result.dev);
        assert_eq!(0, result.inode);
        assert_eq!(true, result.is_r);
        assert_eq!(true, result.is_w);
        assert_eq!(false, result.is_x);
        assert_eq!(true, result.is_p);
        Ok(())
    }

    #[test]
    fn parses_mapping_line_with_file() -> Result<(), SmapError> {
        let input = "5633167c0000-5633167c1000 rw-p 00013000 fd:01 3017058                    /usr/bin/update-notifier";
        let mut result = SmapRange::default();
        parse_smaps_mapping_line_into(&input, &mut result)?;
        assert_eq!(0x5633167c0000, result.address_start);
        assert_eq!(0x5633167c1000, result.address_end);
        assert_eq!(0x13000, result.offset);
        assert_eq!("fd:01", result.dev);
        assert_eq!(3017058, result.inode);
        assert_eq!(Some("/usr/bin/update-notifier"), result.pathname.as_deref());
        assert_eq!(true, result.is_r);
        assert_eq!(true, result.is_w);
        assert_eq!(false, result.is_x);
        assert_eq!(true, result.is_p);
        Ok(())
    }

    #[test]
    fn parses_mapping_line_with_deleted_file() -> Result<(), SmapError> {
        let input = "5633167c0000-5633167c1000 rw-p 00013000 fd:01 3017058                    /usr/bin/update-notifier (deleted)";
        let mut result = SmapRange::default();
        parse_smaps_mapping_line_into(&input, &mut result)?;
        assert_eq!(0x5633167c0000, result.address_start);
        assert_eq!(0x5633167c1000, result.address_end);
        assert_eq!(0x13000, result.offset);
        assert_eq!("fd:01", result.dev);
        assert_eq!(3017058, result.inode);
        assert_eq!(
            Some("/usr/bin/update-notifier (deleted)"),
            result.pathname.as_deref()
        );
        assert_eq!(true, result.is_r);
        assert_eq!(true, result.is_w);
        assert_eq!(false, result.is_x);
        assert_eq!(true, result.is_p);
        Ok(())
    }

    #[test]
    fn detail_line_with_kb() -> Result<(), SmapError> {
        let input = "Size:                  4 kB";
        let mut result = SmapRange::default();
        parse_smaps_detail_line_into(&input, &mut result)?;
        assert_eq!(16384, result.size);
        Ok(())
    }

    #[test]
    fn detail_line_without_kb() -> Result<(), SmapError> {
        let input = "THPeligible:    0";
        let mut result = SmapRange::default();
        parse_smaps_detail_line_into(&input, &mut result)?;
        // no test, just no error
        Ok(())
    }

    #[test]
    fn vmflags_line_multi() {
        let input = "VmFlags: rd ex mr mw me de sd";
        let mut result = SmapRange::default();
        parse_smaps_vmflags_line_into(&input, &mut result);
        assert_eq!(true, result.flag_rd);
        assert_eq!(false, result.flag_wr);
        assert_eq!(true, result.flag_ex);
        assert_eq!(false, result.flag_sh);
        assert_eq!(true, result.flag_mr);
        assert_eq!(true, result.flag_mw);
        assert_eq!(true, result.flag_me);
        assert_eq!(false, result.flag_ms);
        assert_eq!(true, result.flag_de);
        assert_eq!(true, result.flag_sd);
    }

    #[test]
    fn vmflags_line_one() {
        let input = "VmFlags: ex";
        let mut result = SmapRange::default();
        parse_smaps_vmflags_line_into(&input, &mut result);
        assert_eq!(false, result.flag_rd);
        assert_eq!(false, result.flag_wr);
        assert_eq!(true, result.flag_ex);
        assert_eq!(false, result.flag_sh);
        assert_eq!(false, result.flag_mr);
        assert_eq!(false, result.flag_mw);
        assert_eq!(false, result.flag_me);
        assert_eq!(false, result.flag_ms);
        assert_eq!(false, result.flag_de);
        assert_eq!(false, result.flag_sd);
    }

    #[test]
    fn parses() -> Result<(), SmapError> {
        let cargo_toml_root =
            env::var("CARGO_MANIFEST_DIR").expect("should have CARGO_MANIFEST_DIR set");
        let result = read_smaps_file(format!("{cargo_toml_root}/resources/test/smaps.txt"))?;

        assert_eq!(598, result.len());
        let last = result.last().unwrap();
        assert_eq!(4096, last.length);
        assert_eq!("[vsyscall]", last.pathname.as_ref().unwrap());
        assert_eq!(16384, last.mmu_page_size);
        assert_eq!(0, last.lazy_free);
        assert_eq!(false, last.flag_rd);
        assert_eq!(true, last.flag_ex);
        Ok(())
    }
}
