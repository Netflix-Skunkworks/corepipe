// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

use assert_cmd::Command;
use elf::{abi::ET_CORE, endian::AnyEndian, ElfBytes};
#[cfg(target_arch="x86_64")]
use libelf_sys::EM_X86_64;
#[cfg(target_arch="aarch64")]
use libelf_sys::EM_AARCH64;
use ntest::timeout;
use subprocess::{Exec, PopenError};

#[test]
#[ignore]
#[timeout(5000)]
#[cfg(target_arch = "x86_64")]
fn test_sleep_sleeps() -> Result<(), PopenError> {
    // shakeout test to check if sleep will run correctly

    let start = Instant::now();
    let mut sleep_p = Exec::cmd("sleep").arg("2").popen()?;
    assert_eq!(true, sleep_p.pid().is_some());
    let exit_code = sleep_p.wait_timeout(Duration::from_secs(5));

    // should not have timed out
    assert_eq!(true, exit_code.is_ok());
    assert_eq!(true, exit_code.unwrap().is_some());

    // process should have taken more than 2 sec and less than ~2.something, certainly less than 5
    let duration = start.elapsed();
    assert_eq!(true, duration.as_millis() > 2000);
    assert_eq!(true, duration.as_millis() < 4000);

    Ok(())
}

#[test]
#[ignore]
#[timeout(5000)]
#[cfg(target_arch = "x86_64")]
fn test_sleep_was_not_killed() {
    let mut sleep_p = Exec::cmd("sleep").arg("2").popen().unwrap();
    assert_eq!(true, sleep_p.pid().is_some());

    let output = Command::cargo_bin("corepipe")
        .unwrap()
        .arg("--pid")
        .arg(sleep_p.pid().unwrap().to_string())
        .output()
        .expect("failed to execute corepipe");

    assert_eq!(true, output.status.success());
    io::stderr().write_all(&output.stderr).unwrap();

    // process was not terminated
    let exit_code = sleep_p.wait_timeout(Duration::from_secs(5));
    assert_eq!(true, exit_code.is_ok());
    assert_eq!(true, exit_code.unwrap().is_some());
}

#[test]
#[ignore]
#[timeout(5000)]
#[cfg(target_arch = "x86_64")]
fn test_sleep_output_is_parseable() {
    let sleep_p = Exec::cmd("sleep").arg("2").popen().unwrap();
    assert_eq!(true, sleep_p.pid().is_some());

    let output = Command::cargo_bin("corepipe")
        .unwrap()
        .arg("--pid")
        .arg(sleep_p.pid().unwrap().to_string())
        .output()
        .expect("failed to execute corepipe");

    assert_eq!(true, output.status.success());

    // parse the file!
    let elf_bytes_vec = &output.stdout;
    let elf_bytes: &[u8] = &elf_bytes_vec;

    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes).expect("did not parse");

    // what should we find?
    assert_eq!(ET_CORE, elf_file.ehdr.e_type);
    #[cfg(target_arch="x86_64")]
    assert_eq!(EM_X86_64, elf_file.ehdr.e_machine as u32);
    #[cfg(target_arch="aarch64")]
    assert_eq!(EM_AARCH64, elf_file.ehdr.e_machine as u32);

    assert!(elf_file.ehdr.e_phnum > 1);
    assert_eq!(0, elf_file.ehdr.e_shnum);

    // TODO how can we test more about the _contents_ of the dump
}
